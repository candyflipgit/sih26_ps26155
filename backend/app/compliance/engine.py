"""Deterministic compliance evaluation.

This module contains no AI and must never contain any. Given a normalised
configuration and a rule catalogue it produces a verdict by comparison alone,
which is what makes a finding reproducible and defensible: the same inputs
always yield the same output, and every verdict cites the configuration lines
that produced it.

The AI layer's influence stops at the boundary of this module. It may decide
*what the configuration says*; it never decides whether that is compliant.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, computed_field

from app.compliance.rules import ComplianceRule, Operator, RuleCatalog, Severity, Status
from app.schema.normalized import Evidence, NormalizedConfig, SourceType


class Finding(BaseModel):
    """The outcome of evaluating one rule against one device."""

    rule_id: str
    title: str
    status: Status
    severity: Severity
    parameter: str
    operator: Operator
    expected: Any = None
    actual: Any = None
    description: str = ""
    impact: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    # Provenance of the underlying normalised value, carried through so the
    # report can distinguish a parser reading from an AI interpretation.
    source_type: SourceType | None = None
    confidence: float | None = None
    requires_review: bool = False
    normalisation_rationale: str | None = None
    remediation_id: str | None = None
    rule_version: str = "1.0"

    @computed_field
    @property
    def is_ai_assisted(self) -> bool:
        return self.source_type is not None and self.source_type.is_ai_assisted


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def add(self, severity: Severity) -> None:
        setattr(self, severity.value.lower(), getattr(self, severity.value.lower()) + 1)

    @computed_field
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class ScanSummary(BaseModel):
    passed: int = 0
    failed: int = 0
    unknown: int = 0
    not_applicable: int = 0
    # Failures broken down by severity, for the dashboard cards.
    failed_by_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)

    @computed_field
    @property
    def evaluated(self) -> int:
        """Controls that produced a real verdict. UNKNOWN is excluded."""
        return self.passed + self.failed

    @computed_field
    @property
    def score(self) -> float:
        """Percentage of decidable controls that passed.

        UNKNOWN controls are excluded from the denominator rather than counted
        as failures, so an unparsed line lowers *coverage* instead of silently
        inventing a violation.
        """
        if self.evaluated == 0:
            return 0.0
        return round(100.0 * self.passed / self.evaluated, 1)

    @computed_field
    @property
    def coverage(self) -> float:
        """Percentage of applicable controls the engine could actually decide."""
        total = self.evaluated + self.unknown
        if total == 0:
            return 0.0
        return round(100.0 * self.evaluated / total, 1)

    @computed_field
    @property
    def risk_score(self) -> float:
        """Severity-weighted posture, so one CRITICAL outweighs three LOWs."""
        weights = {
            Severity.CRITICAL: self.failed_by_severity.critical,
            Severity.HIGH: self.failed_by_severity.high,
            Severity.MEDIUM: self.failed_by_severity.medium,
            Severity.LOW: self.failed_by_severity.low,
        }
        return float(sum(sev.weight * count for sev, count in weights.items()))


class ScanResult(BaseModel):
    framework: str
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    catalog_version: str = "1.0"
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def failures(self) -> list[Finding]:
        """Failing findings, most severe first."""
        return sorted(
            (f for f in self.findings if f.status is Status.FAIL),
            key=lambda f: (f.severity.rank, f.rule_id),
        )

    @property
    def ai_assisted_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_ai_assisted]


# --- comparison ------------------------------------------------------------

def _compare(operator: Operator, actual: Any, expected: Any) -> bool:
    """Pure comparison. No side effects, no inference, no model in the loop."""
    if operator is Operator.EXISTS:
        return actual is not None
    if operator is Operator.EQUALS:
        return actual == expected
    if operator is Operator.NOT_EQUALS:
        return actual != expected
    if operator is Operator.IN:
        return actual in expected
    if operator is Operator.NOT_IN:
        return actual not in expected

    # Ordered comparisons are only meaningful between numbers. Comparing a bool
    # or a string here would silently produce a nonsense verdict.
    if not isinstance(actual, (int, float)) or isinstance(actual, bool):
        raise TypeError(f"operator {operator.value} needs a numeric value, got {actual!r}")
    if not isinstance(expected, (int, float)) or isinstance(expected, bool):
        raise TypeError(f"operator {operator.value} needs a numeric expectation, got {expected!r}")

    if operator is Operator.GREATER_EQUAL:
        return actual >= expected
    if operator is Operator.LESS_EQUAL:
        return actual <= expected
    if operator is Operator.GREATER_THAN:
        return actual > expected
    if operator is Operator.LESS_THAN:
        return actual < expected

    raise ValueError(f"unhandled operator: {operator}")


def evaluate_rule(rule: ComplianceRule, normalized: NormalizedConfig) -> Finding:
    """Evaluate one rule. Always returns a Finding, never raises."""
    fact = normalized.get(rule.parameter)

    base = dict(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        parameter=rule.parameter,
        operator=rule.operator,
        expected=rule.expected,
        description=rule.description,
        impact=rule.impact,
        frameworks=rule.frameworks,
        remediation_id=rule.remediation_id,
        rule_version=rule.version,
    )

    if fact is None:
        return Finding(
            **base,
            status=Status.UNKNOWN,
            actual=None,
            normalisation_rationale=(
                "No configuration statement was found for this control, and the "
                "vendor rule pack does not define a safe default for it."
            ),
        )

    provenance = dict(
        actual=fact.value,
        evidence=fact.evidence,
        source_type=fact.source_type,
        confidence=fact.confidence,
        requires_review=fact.requires_review,
        normalisation_rationale=fact.rationale,
        references=rule.references(None),
    )

    # A value the vendor uses to mean "unset" or "never" gets an explicit
    # verdict rather than being run through numeric comparison.
    if rule.sentinel is not None and fact.value == rule.sentinel:
        return Finding(**base, **provenance, status=rule.sentinel_status)

    # An AI-derived value that has not been confirmed by an administrator is not
    # a sound basis for asserting compliance. Surfacing it as UNKNOWN keeps the
    # model out of the verdict while still showing what it proposed.
    if fact.requires_review:
        return Finding(**base, **provenance, status=Status.UNKNOWN)

    try:
        ok = _compare(rule.operator, fact.value, rule.expected)
    except (TypeError, ValueError):
        return Finding(**base, **provenance, status=Status.UNKNOWN)

    return Finding(**base, **provenance, status=Status.PASS if ok else Status.FAIL)


def evaluate(
    normalized: NormalizedConfig,
    catalog: RuleCatalog,
    framework: str = "ALL",
) -> ScanResult:
    """Evaluate every applicable rule against a normalised configuration."""
    findings = [evaluate_rule(rule, normalized) for rule in catalog.for_framework(framework)]

    summary = ScanSummary()
    for finding in findings:
        if finding.status is Status.PASS:
            summary.passed += 1
        elif finding.status is Status.FAIL:
            summary.failed += 1
            summary.failed_by_severity.add(finding.severity)
        elif finding.status is Status.UNKNOWN:
            summary.unknown += 1
        else:
            summary.not_applicable += 1

    findings.sort(
        key=lambda f: (
            {Status.FAIL: 0, Status.UNKNOWN: 1, Status.PASS: 2, Status.NOT_APPLICABLE: 3}[f.status],
            f.severity.rank,
            f.rule_id,
        )
    )

    return ScanResult(
        framework=framework,
        findings=findings,
        summary=summary,
        catalog_version=catalog.version,
    )
