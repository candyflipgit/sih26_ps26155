"""Tests for structured (JSON) input, NOT_APPLICABLE controls, and optional
live collection.

The collection tests use an injected fake SSH connection, so the full flow --
platform selection, command set, session cleanup, error mapping, and above all
credential hygiene -- is exercised without a device.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import SecretStr

from app.compliance.engine import evaluate
from app.compliance.rules import RuleCatalog, Status
from app.parsers.detector import detect
from app.parsers.engine import flatten_json, parse
from app.parsers.rulepack import RulePack, RulePackLibrary
from app.services import collector

DATA = Path(__file__).resolve().parent.parent / "data"
SAMPLES = DATA / "samples"
SECRET = "Sup3r-Secret-Passw0rd!"


@pytest.fixture(scope="module")
def library() -> RulePackLibrary:
    return RulePackLibrary(DATA / "knowledge")


@pytest.fixture(scope="module")
def catalog() -> RuleCatalog:
    return RuleCatalog.load(DATA / "rules" / "baseline.json")


def _sg(*permissions, egress=None) -> str:
    return json.dumps({"SecurityGroups": [{
        "GroupName": "test-sg", "GroupId": "sg-0123456789abcdef0",
        "IpPermissions": list(permissions),
        "IpPermissionsEgress": egress or [],
    }]})


def _rule(protocol, low, high, cidr):
    return {"IpProtocol": protocol, "FromPort": low, "ToPort": high,
            "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": [], "UserIdGroupPairs": []}


# --- flattening ------------------------------------------------------------

def test_port_range_and_source_stay_on_one_line() -> None:
    """The relation a rule must see: this port range, open to that source."""
    lines = flatten_json(_sg(_rule("tcp", 22, 22, "0.0.0.0/0"))).splitlines()
    record = next(ln for ln in lines if "IpPermissions[0] " in ln)
    assert "FromPort=22" in record and "IpRanges.CidrIp=0.0.0.0/0" in record


def test_range_enrichment_catches_ports_inside_a_range() -> None:
    """20-23 exposes Telnet and SSH; an exact-port rule would see neither."""
    record = next(ln for ln in flatten_json(_sg(_rule("tcp", 20, 23, "10.0.0.0/8"))).splitlines()
                  if "IpPermissions[0] " in ln)
    assert "covers=22,23" in record
    assert "exposure=restricted" in record


def test_all_protocol_rule_covers_every_management_port() -> None:
    record = next(ln for ln in flatten_json(_sg(_rule("-1", None, None, "0.0.0.0/0"))).splitlines()
                  if "IpPermissions[0] " in ln)
    assert "covers=22,23,3389" in record
    assert "exposure=world" in record


def test_enrichment_is_protocol_aware() -> None:
    """UDP 20-30 does not expose SSH or Telnet, which ride on TCP."""
    record = next(ln for ln in flatten_json(_sg(_rule("udp", 20, 30, "0.0.0.0/0"))).splitlines()
                  if "IpPermissions[0] " in ln)
    assert "covers=" not in record


def test_ipv6_world_is_world() -> None:
    rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "UserIdGroupPairs": []}
    record = next(ln for ln in flatten_json(_sg(rule)).splitlines() if "IpPermissions[0] " in ln)
    assert "exposure=world" in record


def test_invalid_json_is_returned_unchanged() -> None:
    assert flatten_json("not { json") == "not { json"


# --- AWS evaluation --------------------------------------------------------

def _scan(library, catalog, text):
    normalized = parse(text, library.get("aws_security_group"))
    return normalized, evaluate(normalized, catalog, "ALL")


def _status(scan, rule_id):
    return next(f for f in scan.findings if f.rule_id == rule_id).status


def test_bundled_sample_detects_and_identifies(library) -> None:
    text = (SAMPLES / "aws_web_tier_sg.json").read_text(encoding="utf-8")
    assert detect(text, library).vendor == "aws_security_group"
    device = parse(text, library.get("aws_security_group")).device
    assert device.hostname == "web-tier-sg"
    assert device.serial_number == "sg-0a1b2c3d4e5f67890"


def test_bundled_sample_findings(library, catalog) -> None:
    text = (SAMPLES / "aws_web_tier_sg.json").read_text(encoding="utf-8")
    normalized, scan = _scan(library, catalog, text)
    assert _status(scan, "NET-TELNET-001") is Status.FAIL   # via the 20-23 range
    assert _status(scan, "NET-ACL-001") is Status.FAIL      # SSH open to 0.0.0.0/0
    assert scan.summary.not_applicable == 21
    assert scan.summary.unknown == 0
    assert normalized.unknown_commands == []


def test_restricted_ssh_passes(library, catalog) -> None:
    _, scan = _scan(library, catalog, _sg(_rule("tcp", 22, 22, "10.99.0.0/24")))
    assert _status(scan, "NET-ACL-001") is Status.PASS
    assert _status(scan, "NET-TELNET-001") is Status.PASS


def test_one_open_rule_outweighs_restricted_ones(library, catalog) -> None:
    """Risk-first resolution: a single world-open SSH rule is the finding."""
    _, scan = _scan(library, catalog, _sg(
        _rule("tcp", 22, 22, "10.99.0.0/24"), _rule("tcp", 3389, 3389, "0.0.0.0/0"),
    ))
    assert _status(scan, "NET-ACL-001") is Status.FAIL


def test_egress_is_not_mistaken_for_ingress(library, catalog) -> None:
    """Default all-open egress is normal and must not be flagged as exposure."""
    _, scan = _scan(library, catalog, _sg(egress=[_rule("-1", None, None, "0.0.0.0/0")]))
    assert _status(scan, "NET-ACL-001") is Status.PASS
    assert _status(scan, "NET-TELNET-001") is Status.PASS


def test_not_applicable_is_excluded_from_score_and_coverage(library, catalog) -> None:
    _, scan = _scan(library, catalog, _sg(_rule("tcp", 22, 22, "10.99.0.0/24")))
    assert scan.summary.evaluated == 2
    assert scan.summary.score == 100.0
    assert scan.summary.coverage == 100.0


def test_pack_cannot_declare_a_produced_parameter_not_applicable() -> None:
    with pytest.raises(ValueError, match="not applicable"):
        RulePack.model_validate({
            "vendor": "broken", "display_name": "Broken",
            "rules": [{"id": "r1", "parameter": "time.ntp.enabled",
                       "value_rule": "literal:true", "template": "ntp on"}],
            "not_applicable": ["time.ntp.enabled"],
        })


# --- live collection -------------------------------------------------------

class FakeSession:
    def __init__(self, outputs):
        self.outputs, self.sent, self.closed = outputs, [], False

    def send_command(self, command, read_timeout=None):
        self.sent.append(command)
        return self.outputs.get(command, "")

    def disconnect(self):
        self.closed = True


def _fake_connect(session, record):
    def connect(**kwargs):
        record.update(kwargs)
        return session
    return connect


def test_collect_runs_the_platform_command_set_and_disconnects() -> None:
    cisco = (SAMPLES / "cisco_core_switch.cfg").read_text(encoding="utf-8")
    session = FakeSession({"show version": "Cisco IOS Software", "show running-config": cisco})
    seen: dict = {}
    result = collector.collect("10.0.0.1", "cisco_ios", "auditor", SecretStr(SECRET),
                               connect=_fake_connect(session, seen))
    assert session.sent == ["show version", "show running-config"]
    assert session.closed
    assert seen["device_type"] == "cisco_ios"
    assert "# show running-config" in result.text and "hostname CORE-SW-01" in result.text


def test_collect_rejects_unsupported_platform() -> None:
    with pytest.raises(collector.CollectionError) as err:
        collector.collect("10.0.0.1", "nokia_sros", "u", SecretStr(SECRET), connect=lambda **k: None)
    assert err.value.status == 422


@pytest.mark.parametrize("host", ["", "10.0.0.1; rm -rf /", "host name with spaces"])
def test_collect_rejects_malformed_host(host) -> None:
    with pytest.raises(collector.CollectionError) as err:
        collector.collect(host, "cisco_ios", "u", SecretStr(SECRET), connect=lambda **k: None)
    assert err.value.status == 422


def test_driver_failure_never_leaks_the_password(caplog) -> None:
    """A driver exception can echo connection details; the secret must not follow."""
    def exploding(**kwargs):
        raise RuntimeError(f"boom while using {kwargs['password']}")

    with caplog.at_level(logging.DEBUG), pytest.raises(collector.CollectionError) as err:
        collector.collect("10.0.0.1", "cisco_ios", "u", SecretStr(SECRET), connect=exploding)
    assert err.value.status == 502
    assert SECRET not in str(err.value)
    assert err.value.__cause__ is None and err.value.__suppress_context__
    assert SECRET not in caplog.text


def test_session_is_closed_even_when_a_command_fails() -> None:
    class Failing(FakeSession):
        def send_command(self, command, read_timeout=None):
            raise RuntimeError("channel dropped")

    session = Failing({})
    with pytest.raises(collector.CollectionError):
        collector.collect("10.0.0.1", "cisco_ios", "u", SecretStr(SECRET),
                          connect=_fake_connect(session, {}))
    assert session.closed


@pytest.mark.skipif(not collector.netmiko_available(), reason="netmiko not installed")
def test_real_driver_reports_an_unreachable_device() -> None:
    """Nothing listens on port 1; the real driver must fail fast and cleanly."""
    with pytest.raises(collector.CollectionError) as err:
        collector.collect("127.0.0.1", "cisco_ios", "u", SecretStr(SECRET), port=1, timeout=3)
    assert err.value.status in (502, 504)
    assert SECRET not in str(err.value)


def test_collect_endpoint_analyses_what_it_collected(client, monkeypatch) -> None:
    cisco = (SAMPLES / "cisco_core_switch.cfg").read_text(encoding="utf-8")
    real_collect = collector.collect

    def fake(host, platform, username, password, port, timeout):
        session = FakeSession({"show version": "", "show running-config": cisco})
        return real_collect(host, platform, username, password, port, timeout,
                            connect=_fake_connect(session, {}))

    monkeypatch.setattr(collector, "collect", fake)
    response = client.post("/api/v1/collect", json={
        "host": "10.0.0.1", "platform": "cisco_ios", "username": "auditor", "password": SECRET,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["normalized"]["device"]["hostname"] == "CORE-SW-01"
    assert body["collection"]["commands"] == ["show version", "show running-config"]
    assert SECRET not in response.text


def test_collect_endpoint_maps_errors_without_echoing_secrets(client) -> None:
    response = client.post("/api/v1/collect", json={
        "host": "10.0.0.1", "platform": "not-a-platform", "username": "u", "password": SECRET,
    })
    assert response.status_code == 422
    assert SECRET not in response.text


def test_platform_listing(client) -> None:
    body = client.get("/api/v1/collect/platforms").json()
    vendors = {p["vendor"] for p in body["platforms"]}
    assert {"cisco_ios", "juniper_junos", "fortinet_fortios", "paloalto_panos"} <= vendors
