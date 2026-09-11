"""Tests for bulk ingestion, fleet scoring, release-aware remediation and the
Palo Alto pack.

The API tests run the real FastAPI app against a throwaway copy of the data
directory, with inference disabled, so they never touch the working knowledge
base, the real database, or a live model endpoint.
"""

from __future__ import annotations

import io
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from app.compliance.remediation import RemediationLibrary, version_key
from app.parsers.detector import detect
from app.parsers.engine import parse
from app.parsers.rulepack import RulePackLibrary

DATA = Path(__file__).resolve().parent.parent / "data"
SAMPLES = DATA / "samples"


# --- Palo Alto pack --------------------------------------------------------

@pytest.fixture(scope="module")
def library() -> RulePackLibrary:
    return RulePackLibrary(DATA / "knowledge")


def test_paloalto_detected_with_full_identity(library: RulePackLibrary) -> None:
    text = (SAMPLES / "paloalto_datacenter_fw.conf").read_text(encoding="utf-8")
    assert detect(text, library).vendor == "paloalto_panos"
    device = parse(text, library.get("paloalto_panos")).device
    assert device.hostname == "DC-PA-01"
    assert device.model == "PA-3220"
    assert device.serial_number == "016401009876"
    assert device.os_version == "10.2.9"


@pytest.mark.parametrize(
    "parameter,value",
    [
        ("management.telnet.enabled", True),
        ("management.http.enabled", True),
        ("snmp.default_community.present", True),
        ("snmp.insecure_version_enabled", True),
        ("authentication.default_accounts.present", True),
        ("authentication.password.min_length", 8),
        ("access.idle_timeout.seconds", 3600),
        ("access.management_acl.enabled", False),
        ("time.ntp.authenticated", False),
        ("logging.remote_syslog.enabled", True),
    ],
)
def test_paloalto_normalised_values(library: RulePackLibrary, parameter: str, value: object) -> None:
    text = (SAMPLES / "paloalto_datacenter_fw.conf").read_text(encoding="utf-8")
    fact = parse(text, library.get("paloalto_panos")).get(parameter)
    assert fact is not None, parameter
    assert fact.value == value


def test_every_sample_detects_as_its_own_vendor(library: RulePackLibrary) -> None:
    """Adding a pack must not let it steal another vendor's configurations."""
    expected = {
        "cisco_core_switch.cfg": "cisco_ios",
        "juniper_edge_srx.conf": "juniper_junos",
        "fortinet_perimeter_fw.conf": "fortinet_fortios",
        "paloalto_datacenter_fw.conf": "paloalto_panos",
        "mikrotik_branch_router.rsc": "unknown",
    }
    for name, vendor in expected.items():
        assert detect((SAMPLES / name).read_text(encoding="utf-8"), library).vendor == vendor, name


# --- release-aware remediation ---------------------------------------------

@pytest.mark.parametrize(
    "raw,key",
    [
        ("17.09.04a", (17, 9, 4)),
        ("15.2(4)M", (15, 2, 4)),
        ("21.4R3-S5.4", (21, 4, 3)),
        ("v7.4.4", (7, 4, 4)),
        ("10.2.9", (10, 2, 9)),
        (None, None),
        ("", None),
    ],
)
def test_version_key(raw, key) -> None:
    assert version_key(raw) == key


@pytest.fixture(scope="module")
def remediation() -> RemediationLibrary:
    return RemediationLibrary(DATA / "rules" / "remediation.json")


def test_modern_release_gets_modern_syntax(remediation: RemediationLibrary) -> None:
    plan = remediation.plan_for("REM-AUTH-001", "cisco_ios", "17.09.04a")
    assert any("scrypt" in c for c in plan.commands)
    assert "17.09.04a" in plan.version_basis


def test_legacy_release_gets_legacy_syntax(remediation: RemediationLibrary) -> None:
    """Handing an old release a command it rejects is nearly as bad as a wrong one."""
    plan = remediation.plan_for("REM-AUTH-001", "cisco_ios", "15.2(4)M")
    assert not any("scrypt" in c for c in plan.commands)
    assert any("enable secret" in c for c in plan.commands)
    assert "before 15.3" in plan.version_basis


def test_undetected_version_is_admitted_not_implied(remediation: RemediationLibrary) -> None:
    plan = remediation.plan_for("REM-AUTH-001", "cisco_ios", None)
    assert "not detected" in plan.version_basis


def test_template_without_variants_makes_no_version_claim(remediation: RemediationLibrary) -> None:
    plan = remediation.plan_for("REM-TELNET-001", "juniper_junos", "21.4R3")
    assert plan.version_basis == ""


def test_boundary_version_is_inclusive_below_exclusive_above(remediation: RemediationLibrary) -> None:
    at_boundary = remediation.plan_for("REM-SSH-003", "cisco_ios", "15.5.1")
    below = remediation.plan_for("REM-SSH-003", "cisco_ios", "15.4.9")
    assert any("algorithm" in c for c in at_boundary.commands)
    assert not any("algorithm" in c for c in below.commands)


# --- the API: batch, fleet scoring, report bundle --------------------------
# The `client` fixture lives in conftest.py, shared with the collection tests.

def _files(*names: str):
    return [("files", (n, (SAMPLES / n).read_bytes(), "text/plain")) for n in names]


def test_batch_isolates_a_bad_file(client) -> None:
    files = _files("cisco_core_switch.cfg", "juniper_edge_srx.conf")
    files.append(("files", ("empty.cfg", b"", "text/plain")))
    body = client.post("/api/v1/configs/upload-batch", files=files).json()
    assert body["analysed"] == 2
    assert body["failed_files"] == 1
    assert body["errors"][0]["filename"] == "empty.cfg"


def test_fleet_average_ignores_undecidable_devices(client) -> None:
    """An unrecognised vendor scores 0 only because 0/0 must print as something."""
    cisco = client.post(
        "/api/v1/configs/upload-batch", files=_files("cisco_core_switch.cfg")
    ).json()["results"][0]
    body = client.post(
        "/api/v1/configs/upload-batch",
        files=_files("cisco_core_switch.cfg", "mikrotik_branch_router.rsc"),
    ).json()
    fleet = body["fleet"]
    assert fleet["devices_judged"] == 1
    assert fleet["unknown_vendors"] == 1
    assert fleet["average_score"] == cisco["score"]


def test_batch_is_sorted_worst_first(client) -> None:
    body = client.post(
        "/api/v1/configs/upload-batch",
        files=_files("juniper_edge_srx.conf", "cisco_core_switch.cfg", "fortinet_perimeter_fw.conf"),
    ).json()
    scores = [r["score"] for r in body["results"]]
    assert scores == sorted(scores)


def test_report_bundle_holds_one_pdf_per_device(client) -> None:
    results = client.post(
        "/api/v1/configs/upload-batch",
        files=_files("cisco_core_switch.cfg", "juniper_edge_srx.conf", "paloalto_datacenter_fw.conf"),
    ).json()["results"]
    response = client.post(
        "/api/v1/batch/reports", json={"config_ids": [r["config_id"] for r in results]}
    )
    assert response.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(response.content)).namelist()
    assert len(names) == 3
    assert len(set(names)) == 3
    assert all(n.endswith(".pdf") for n in names)


def test_single_report_route_is_not_shadowed(client) -> None:
    """/batch/reports exists precisely so /reports/{id} keeps working."""
    result = client.post("/api/v1/samples/cisco_core_switch.cfg/analyze").json()
    response = client.post(f"/api/v1/reports/{result['config_id']}")
    assert response.status_code == 200


def test_remediation_endpoint_is_release_aware(client) -> None:
    result = client.post("/api/v1/samples/cisco_core_switch.cfg/analyze").json()
    plan = client.get(
        f"/api/v1/analyses/{result['config_id']}/remediation/NET-AUTH-001"
    ).json()
    assert "17.09.04a" in plan["version_basis"]
