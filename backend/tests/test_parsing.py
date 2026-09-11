"""Tests for canonicalisation and the vendor-agnostic parsing engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ai.canonicalize import apply_value_rule, canonicalize
from app.parsers.engine import is_security_relevant, parse
from app.parsers.rulepack import RulePackLibrary
from app.schema.normalized import Evidence, NormalizedConfig, NormalizedFact, SourceType

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def library() -> RulePackLibrary:
    return RulePackLibrary(DATA / "knowledge")


@pytest.fixture(scope="module")
def cisco(library: RulePackLibrary) -> NormalizedConfig:
    pack = library.get("cisco_ios")
    assert pack is not None
    return parse((DATA / "samples" / "cisco_core_switch.cfg").read_text(encoding="utf-8"), pack)


# --- canonicalisation ------------------------------------------------------

@pytest.mark.parametrize(
    "line,template,slots",
    [
        ("ip ssh version 2", "ip ssh version <NUM>", ["2"]),
        ("  NTP   server  10.10.10.10 ", "ntp server <IP>", ["10.10.10.10"]),
        ("exec-timeout 10 0", "exec-timeout <NUM> <NUM>", ["10", "0"]),
        ("permit ip 10.0.0.0/8 any", "permit ip <CIDR> any", ["10.0.0.0/8"]),
        ("/ip ssh set strong-crypto=yes", "/ip ssh set strong-crypto=yes", []),
    ],
)
def test_canonicalize(line: str, template: str, slots: list[str]) -> None:
    assert canonicalize(line) == (template, slots)


def test_template_generalises_across_values() -> None:
    """Teaching one value must teach the command shape, not the literal string."""
    learned, _ = canonicalize("ip ssh version 2")
    seen, slots = canonicalize("ip ssh version 1")
    assert learned == seen
    assert apply_value_rule("slot:0", slots) == "1"


def test_version_token_does_not_collide_with_setting_name() -> None:
    """FortiOS puts the version in the key, so these must stay distinguishable."""
    assert canonicalize("set admin-ssh-v1 disable")[0] != canonicalize("set admin-ssh-v2 disable")[0]


def test_junos_version_token_generalises() -> None:
    a, a_slots = canonicalize("set system services ssh protocol-version v2")
    b, b_slots = canonicalize("set system services ssh protocol-version v1")
    assert a == b
    assert apply_value_rule("slot:0:digits", a_slots) == 2
    assert apply_value_rule("slot:0:digits", b_slots) == 1


@pytest.mark.parametrize(
    "rule,slots,expected",
    [
        ("literal:true", [], True),
        ("literal:false", [], False),
        ("literal:42", [], 42),
        ("slot:0", ["7"], "7"),
        ("slot:0:minutes_to_seconds", ["10"], 600),
        ("slot:0:digits", ["v2"], 2),
        ("slot:0:negate", ["yes"], False),
    ],
)
def test_value_rules(rule: str, slots: list[str], expected: object) -> None:
    assert apply_value_rule(rule, slots) == expected


def test_value_rule_rejects_missing_slot() -> None:
    with pytest.raises(ValueError):
        apply_value_rule("slot:3", ["only-one"])


# --- relevance filtering ---------------------------------------------------

def test_security_relevance_filter() -> None:
    assert is_security_relevant("ip ssh version <NUM>")
    assert is_security_relevant("snmp-server community public ro")
    assert not is_security_relevant("switchport mode trunk")
    assert not is_security_relevant("spanning-tree mode rapid-pvst")
    assert not is_security_relevant("name USERS")


# --- Cisco parsing ---------------------------------------------------------

def test_device_identity_including_serial(cisco: NormalizedConfig) -> None:
    """The problem statement requires serial and hardware details in the report."""
    d = cisco.device
    assert d.hostname == "CORE-SW-01"
    assert d.serial_number == "FCW2447L0GH"
    assert d.model == "C9300-48P"
    assert d.os_version == "17.09.04a"


@pytest.mark.parametrize(
    "parameter,value",
    [
        ("management.ssh.version", 2),
        ("management.telnet.enabled", True),
        ("management.http.enabled", True),
        ("management.https.enabled", True),
        ("authentication.aaa.enabled", False),
        ("authentication.password.encryption_enabled", True),
        ("authentication.privileged.protected", True),
        ("authentication.default_accounts.present", True),
        ("snmp.default_community.present", True),
        ("services.source_routing.enabled", True),
        ("access.idle_timeout.seconds", 1800),
        ("time.ntp.enabled", True),
        ("time.ntp.authenticated", False),
    ],
)
def test_cisco_normalised_values(cisco: NormalizedConfig, parameter: str, value: object) -> None:
    fact = cisco.get(parameter)
    assert fact is not None, f"{parameter} was not normalised"
    assert fact.value == value


def test_one_line_can_assert_several_parameters(cisco: NormalizedConfig) -> None:
    """`transport input telnet ssh` says something about both protocols."""
    assert cisco.get("management.telnet.enabled").value is True
    assert cisco.get("management.ssh.enabled").value is True


def test_conflicting_vty_blocks_resolve_to_the_risky_value(cisco: NormalizedConfig) -> None:
    """One VTY range permits Telnet, another does not. The exposure must win."""
    telnet = cisco.get("management.telnet.enabled")
    assert telnet.value is True
    # Both contributing lines are cited, so the report can justify the verdict.
    assert len(telnet.evidence) >= 2


def test_absence_is_recorded_with_a_rationale(cisco: NormalizedConfig) -> None:
    ntp_auth = cisco.get("time.ntp.authenticated")
    assert ntp_auth.value is False
    assert ntp_auth.evidence == []
    assert ntp_auth.rationale


def test_block_headers_do_not_reach_the_training_queue(cisco: NormalizedConfig) -> None:
    raws = [u.raw.lower() for u in cisco.unknown_commands]
    assert not any(r.startswith("line vty") for r in raws)
    assert not any(r.startswith("interface ") for r in raws)


def test_unknown_queue_holds_only_security_relevant_lines(cisco: NormalizedConfig) -> None:
    assert cisco.unknown_commands, "sample should leave something to teach"
    for unknown in cisco.unknown_commands:
        assert is_security_relevant(unknown.canonical)


def test_coverage_is_reported(cisco: NormalizedConfig) -> None:
    assert cisco.stats.significant_lines > 0
    assert 0 < cisco.stats.coverage <= 100


# --- provenance ------------------------------------------------------------

def test_deterministic_parser_outranks_llm_for_the_same_parameter() -> None:
    """An LLM guess must never override a value the parser read directly."""
    config = NormalizedConfig(
        device=cisco_identity(),
        facts=[
            NormalizedFact(
                parameter="management.telnet.enabled", value=True, confidence=1.0,
                source_type=SourceType.DETERMINISTIC_PARSER,
                evidence=[Evidence(line_number=1, text="transport input telnet")],
            ),
            NormalizedFact(
                parameter="management.telnet.enabled", value=False, confidence=0.99,
                source_type=SourceType.LLM,
            ),
        ],
    )
    winner = config.get("management.telnet.enabled")
    assert winner.value is True
    assert winner.source_type is SourceType.DETERMINISTIC_PARSER


def cisco_identity():
    from app.schema.normalized import DeviceIdentity

    return DeviceIdentity(vendor="cisco_ios")


def test_unknown_parameter_is_rejected() -> None:
    with pytest.raises(ValueError):
        NormalizedFact(
            parameter="management.ssh.notARealThing", value=1, confidence=1.0,
            source_type=SourceType.LLM,
        )
