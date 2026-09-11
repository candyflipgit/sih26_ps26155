"""Tests for the deterministic compliance engine and the learning loop.

The properties asserted here are the ones the project's credibility rests on:
that an undetermined reading never becomes a failure, that an AI proposal never
becomes a verdict on its own, and that an approved mapping takes effect
immediately and generalises.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app.compliance.engine import evaluate, evaluate_rule
from app.compliance.remediation import RemediationLibrary
from app.compliance.rules import ComplianceRule, Operator, RuleCatalog, Severity, Status
from app.schema.normalized import (
    DeviceIdentity, Evidence, NormalizedConfig, NormalizedFact, SourceType,
)

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def catalog() -> RuleCatalog:
    return RuleCatalog.load(DATA / "rules" / "baseline.json")


@pytest.fixture(scope="module")
def remediation() -> RemediationLibrary:
    return RemediationLibrary(DATA / "rules" / "remediation.json")


def config_with(*facts: NormalizedFact) -> NormalizedConfig:
    return NormalizedConfig(device=DeviceIdentity(vendor="cisco_ios"), facts=list(facts))


def fact(parameter, value, source=SourceType.DETERMINISTIC_PARSER, confidence=1.0, review=False):
    return NormalizedFact(
        parameter=parameter, value=value, confidence=confidence, source_type=source,
        evidence=[Evidence(line_number=1, text="synthetic")], requires_review=review,
    )


# --- catalogue integrity ---------------------------------------------------

def test_every_control_maps_to_all_four_frameworks(catalog: RuleCatalog) -> None:
    """The multi-framework claim has to hold for every control, not just some."""
    expected = {"CIS", "NIST", "STIG", "ISO27001"}
    for rule in catalog.rules:
        assert set(rule.frameworks) == expected, f"{rule.id} is missing a framework mapping"
        for key, refs in rule.frameworks.items():
            assert refs, f"{rule.id} has an empty {key} mapping"


def test_every_control_has_impact_text(catalog: RuleCatalog) -> None:
    for rule in catalog.rules:
        assert rule.impact, f"{rule.id} has no explanation of why it matters"


def test_every_control_has_a_remediation_template(
    catalog: RuleCatalog, remediation: RemediationLibrary
) -> None:
    for rule in catalog.rules:
        assert rule.remediation_id in remediation.templates, rule.id


def test_framework_filter_selects_a_subset(catalog: RuleCatalog) -> None:
    assert len(catalog.for_framework("CIS")) > 0
    assert len(catalog.for_framework("ALL")) == len(catalog.rules)
    assert len(catalog.for_framework("NOT-A-FRAMEWORK")) == 0


# --- verdicts --------------------------------------------------------------

def test_pass_and_fail(catalog: RuleCatalog) -> None:
    rule = catalog.get("NET-TELNET-001")
    assert evaluate_rule(rule, config_with(fact(rule.parameter, False))).status is Status.PASS
    assert evaluate_rule(rule, config_with(fact(rule.parameter, True))).status is Status.FAIL


def test_missing_parameter_is_unknown_not_failure(catalog: RuleCatalog) -> None:
    """The single most important property: absence of data is not a violation."""
    rule = catalog.get("NET-TELNET-001")
    finding = evaluate_rule(rule, config_with())
    assert finding.status is Status.UNKNOWN
    assert finding.status is not Status.FAIL
    assert finding.normalisation_rationale


def test_unknown_is_excluded_from_score_not_counted_as_failure(catalog: RuleCatalog) -> None:
    result = evaluate(
        config_with(
            fact("management.telnet.enabled", False),
            fact("management.http.enabled", False),
        ),
        catalog,
        "ALL",
    )
    assert result.summary.passed == 2
    assert result.summary.failed == 0
    assert result.summary.unknown == len(catalog.rules) - 2
    # Two of two decidable controls passed, so the score is 100 even though
    # coverage is low. Conflating the two is what produces false positives.
    assert result.summary.score == 100.0
    assert result.summary.coverage < 100.0


def test_ai_reading_awaiting_review_cannot_produce_a_verdict(catalog: RuleCatalog) -> None:
    """An unreviewed model proposal must not decide compliance either way."""
    rule = catalog.get("NET-TELNET-001")
    compliant_looking = fact(
        rule.parameter, False, source=SourceType.LLM, confidence=0.97, review=True
    )
    finding = evaluate_rule(rule, config_with(compliant_looking))
    assert finding.status is Status.UNKNOWN
    assert finding.is_ai_assisted
    assert finding.confidence == 0.97


def test_approved_knowledge_base_reading_does_produce_a_verdict(catalog: RuleCatalog) -> None:
    """Once an administrator has approved the mapping, it counts."""
    rule = catalog.get("NET-TELNET-001")
    approved = fact(rule.parameter, True, source=SourceType.KNOWLEDGE_BASE, review=False)
    assert evaluate_rule(rule, config_with(approved)).status is Status.FAIL


def test_sentinel_value_is_handled_explicitly(catalog: RuleCatalog) -> None:
    """exec-timeout 0 means 'never expires', which must fail despite being <= 600."""
    rule = catalog.get("NET-TIMEOUT-001")
    assert rule.sentinel == 0
    assert evaluate_rule(rule, config_with(fact(rule.parameter, 0))).status is Status.FAIL
    assert evaluate_rule(rule, config_with(fact(rule.parameter, 300))).status is Status.PASS
    assert evaluate_rule(rule, config_with(fact(rule.parameter, 1800))).status is Status.FAIL


def test_type_mismatch_degrades_to_unknown_not_a_crash() -> None:
    """A malformed reading must never take down a scan or invent a verdict."""
    rule = ComplianceRule(
        id="T-1", title="numeric", parameter="authentication.password.min_length",
        operator=Operator.GREATER_EQUAL, expected=12, severity=Severity.MEDIUM,
        description="", impact="x",
    )
    finding = evaluate_rule(rule, config_with(fact(rule.parameter, True)))
    assert finding.status is Status.UNKNOWN


def test_riskier_reading_wins_when_observations_disagree() -> None:
    """Two VTY blocks disagree about Telnet; the exposure must not be hidden."""
    config = config_with(
        NormalizedFact(
            parameter="management.telnet.enabled", value=False, confidence=1.0,
            source_type=SourceType.DETERMINISTIC_PARSER,
            evidence=[Evidence(line_number=90, text="transport input ssh")],
        ),
        NormalizedFact(
            parameter="management.telnet.enabled", value=True, confidence=1.0,
            source_type=SourceType.DETERMINISTIC_PARSER,
            evidence=[Evidence(line_number=86, text="transport input telnet ssh")],
        ),
    )
    resolved = config.get("management.telnet.enabled")
    assert resolved.value is True
    assert [e.line_number for e in resolved.evidence] == [86, 90]


def test_scoring_arithmetic(catalog: RuleCatalog) -> None:
    result = evaluate(
        config_with(
            fact("management.telnet.enabled", True),     # FAIL, critical
            fact("management.http.enabled", False),      # PASS
            fact("management.https.enabled", True),      # PASS
        ),
        catalog, "ALL",
    )
    assert result.summary.passed == 2
    assert result.summary.failed == 1
    assert result.summary.score == round(100 * 2 / 3, 1)
    assert result.summary.failed_by_severity.critical == 1
    assert result.summary.risk_score == Severity.CRITICAL.weight


def test_failures_are_ordered_most_severe_first(catalog: RuleCatalog) -> None:
    result = evaluate(
        config_with(
            fact("access.login_banner.present", False),      # LOW
            fact("management.telnet.enabled", True),         # CRITICAL
            fact("logging.remote_syslog.enabled", False),    # HIGH
        ),
        catalog, "ALL",
    )
    severities = [f.severity for f in result.failures]
    assert severities == sorted(severities, key=lambda s: s.rank)
    assert result.failures[0].severity is Severity.CRITICAL


# --- remediation -----------------------------------------------------------

def test_remediation_is_vendor_specific(remediation: RemediationLibrary) -> None:
    cisco = remediation.plan_for("REM-TELNET-001", "cisco_ios")
    junos = remediation.plan_for("REM-TELNET-001", "juniper_junos")
    assert cisco.vendor_specific and junos.vendor_specific
    assert cisco.commands != junos.commands
    assert any("transport input ssh" in c for c in cisco.commands)
    assert any("delete system services telnet" in c for c in junos.commands)


def test_unknown_vendor_gets_guidance_not_invented_commands(
    remediation: RemediationLibrary,
) -> None:
    """Fabricating a CLI command for an unsupported platform is worse than none."""
    plan = remediation.plan_for("REM-TELNET-001", "some_vendor_we_do_not_support")
    assert plan.vendor_specific is False
    assert plan.commands == []
    assert plan.guidance


def test_every_remediation_carries_a_review_warning(remediation: RemediationLibrary) -> None:
    plan = remediation.plan_for("REM-TELNET-001", "cisco_ios")
    assert "change-control" in plan.warning


# --- the learning loop -----------------------------------------------------

@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """A throwaway copy of the data directory, so tests never mutate real packs.

    Any rule learned during a demo or a manual session is stripped, so these
    tests assert against the shipped baseline rather than against whatever
    happens to be in the working copy.
    """
    target = tmp_path / "data"
    shutil.copytree(DATA, target, ignore=shutil.ignore_patterns("*.db", "reports", "uploads"))

    for path in (target / "knowledge").glob("*.json"):
        pack = json.loads(path.read_text(encoding="utf-8"))
        pack["rules"] = [r for r in pack.get("rules", []) if r.get("origin", "builtin") != "learned"]
        path.write_text(json.dumps(pack, indent=2), encoding="utf-8")

    return target


def test_teaching_a_command_makes_it_recognised_and_generalised(sandbox: Path) -> None:
    from app.core.config import Settings
    from app.services.analysis import AnalysisEngine

    settings = Settings(
        data_dir=sandbox,
        database_url=f"sqlite:///{(sandbox / 'test.db').as_posix()}",
        llm_api_key="",
    )
    engine = AnalysisEngine(settings)
    sample = (sandbox / "samples" / "mikrotik_branch_router.rsc").read_text(encoding="utf-8")

    before = engine.analyze(sample, "m.rsc", "ALL")
    assert before.detection.vendor == "unknown"
    assert before.normalized.get("management.telnet.enabled") is None
    queue_before = len(before.normalized.unknown_commands)

    engine.teach(
        "generic", "/ip service set telnet disabled=no port=23",
        "management.telnet.enabled", True, "tester",
    )

    after = engine.analyze(sample, "m.rsc", "ALL")
    resolved = after.normalized.get("management.telnet.enabled")
    assert resolved is not None
    assert resolved.value is True
    assert resolved.source_type is SourceType.KNOWLEDGE_BASE
    assert len(after.normalized.unknown_commands) == queue_before - 1

    telnet = next(f for f in after.scan.findings if f.rule_id == "NET-TELNET-001")
    assert telnet.status is Status.FAIL
    assert telnet.severity is Severity.CRITICAL

    # The taught rule must match a variant it has never seen, proving the system
    # learned the command's shape rather than the literal string.
    variant = engine.analyze(
        "/system identity set name=PROBE\n/ip service set telnet disabled=no port=2323\n",
        "probe.rsc", "ALL",
    )
    assert variant.normalized.get("management.telnet.enabled").value is True


def test_learned_rule_is_persisted_to_the_pack_on_disk(sandbox: Path) -> None:
    """Learning must survive a restart, or it is not learning."""
    from app.core.config import Settings
    from app.services.analysis import AnalysisEngine

    settings = Settings(
        data_dir=sandbox,
        database_url=f"sqlite:///{(sandbox / 'test.db').as_posix()}",
        llm_api_key="",
    )
    AnalysisEngine(settings).teach(
        "generic", "/snmp set enabled=yes", "snmp.enabled", True, "tester"
    )

    written = json.loads((sandbox / "knowledge" / "generic.json").read_text(encoding="utf-8"))
    learned = [r for r in written["rules"] if r.get("origin") == "learned"]
    assert len(learned) == 1
    assert learned[0]["parameter"] == "snmp.enabled"
    assert learned[0]["approved_by"] == "tester"
    assert learned[0]["approved_at"]

    # A fresh engine, as if the process had restarted, must still know it.
    reloaded = AnalysisEngine(settings)
    result = reloaded.analyze("/snmp set enabled=yes\n", "x.rsc", "ALL")
    assert result.normalized.get("snmp.enabled").value is True


def test_integer_mapping_learns_a_slot_rule_not_a_literal(sandbox: Path) -> None:
    """Teaching a timeout of 10 must also read a timeout of 30."""
    from app.core.config import Settings
    from app.services.analysis import AnalysisEngine

    settings = Settings(
        data_dir=sandbox,
        database_url=f"sqlite:///{(sandbox / 'test.db').as_posix()}",
        llm_api_key="",
    )
    engine = AnalysisEngine(settings)
    rule = engine.teach(
        "generic", "/ip ssh set idle-timeout=600", "access.idle_timeout.seconds", 600, "tester"
    )
    assert rule.value_rule.startswith("slot:"), rule.value_rule

    result = engine.analyze("/ip ssh set idle-timeout=1800\n", "x.rsc", "ALL")
    assert result.normalized.get("access.idle_timeout.seconds").value == 1800
