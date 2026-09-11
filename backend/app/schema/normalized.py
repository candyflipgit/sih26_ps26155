"""The vendor-neutral Security Baseline Model.

A parsed configuration collapses into a list of `NormalizedFact` objects plus a
`DeviceIdentity`. Every fact carries its provenance -- which subsystem produced
it, how confident that subsystem was, and the literal configuration lines it was
derived from. That provenance chain is what lets a finding be traced from raw
text all the way to a PASS/FAIL verdict.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator

from app.schema.parameters import PARAMETER_INDEX, riskier


class SourceType(str, Enum):
    """How a normalized fact came to exist. Ordered most to least trusted."""

    DETERMINISTIC_PARSER = "deterministic_parser"  # vendor parser matched a known pattern
    KNOWLEDGE_BASE = "knowledge_base"              # admin-approved mapping, exact template hit
    RETRIEVAL = "retrieval"                        # near-duplicate of an approved mapping
    LLM = "llm"                                    # model proposed it, schema-validated
    MANUAL = "manual"                              # an administrator typed it directly

    @property
    def is_ai_assisted(self) -> bool:
        return self in (SourceType.RETRIEVAL, SourceType.LLM)


class Evidence(BaseModel):
    """A literal slice of the source configuration."""

    line_number: int = Field(ge=0)
    text: str

    def __str__(self) -> str:
        return f"L{self.line_number}: {self.text}"


class NormalizedFact(BaseModel):
    """One canonical security parameter observed on a device."""

    parameter: str
    value: Any
    confidence: float = Field(ge=0.0, le=1.0)
    source_type: SourceType
    evidence: list[Evidence] = Field(default_factory=list)
    # Populated when an AI subsystem produced the fact, for the UI and report.
    rationale: str | None = None
    requires_review: bool = False

    @field_validator("parameter")
    @classmethod
    def _known_parameter(cls, v: str) -> str:
        if v not in PARAMETER_INDEX:
            raise ValueError(f"'{v}' is not in the canonical parameter registry")
        return v

    @property
    def evidence_text(self) -> str:
        return "\n".join(e.text for e in self.evidence)


class UnknownCommand(BaseModel):
    """A configuration line no subsystem could confidently interpret.

    These are not failures -- they are the queue that feeds the Teach-AI screen.
    """

    raw: str
    canonical: str
    line_number: int
    vendor_hint: str | None = None
    # The enclosing configuration block, e.g. "config log syslogd setting" or
    # "line vty 0 4". Carried through to the AI layer because a line like
    # `set status enable` is meaningless without it -- CAIP (arXiv:2411.14283)
    # measured a ~30% detection-accuracy gain from supplying exactly this.
    context: str = ""
    # Best-effort AI proposal, if one was produced but scored below threshold.
    suggested_parameter: str | None = None
    suggested_value: Any = None
    suggested_confidence: float | None = None
    suggested_rationale: str | None = None


class DeviceIdentity(BaseModel):
    """Device identification, required by the problem statement's report spec."""

    hostname: str | None = None
    vendor: str = "unknown"
    os_family: str | None = None
    os_version: str | None = None
    model: str | None = None
    serial_number: str | None = None

    @computed_field
    @property
    def display_name(self) -> str:
        return self.hostname or self.model or f"{self.vendor} device"


class NormalizationStats(BaseModel):
    """Coverage metrics surfaced on the analysis screen."""

    total_lines: int = 0
    significant_lines: int = 0     # non-blank, non-comment
    interpreted_lines: int = 0
    unknown_lines: int = 0
    facts_by_source: dict[str, int] = Field(default_factory=dict)

    @computed_field
    @property
    def coverage(self) -> float:
        if self.significant_lines == 0:
            return 0.0
        return round(100.0 * self.interpreted_lines / self.significant_lines, 1)


class NormalizedConfig(BaseModel):
    """Full normalized representation of one uploaded configuration."""

    device: DeviceIdentity
    facts: list[NormalizedFact] = Field(default_factory=list)
    unknown_commands: list[UnknownCommand] = Field(default_factory=list)
    stats: NormalizationStats = Field(default_factory=NormalizationStats)
    normalized_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get(self, parameter: str) -> NormalizedFact | None:
        """Return the authoritative fact for a parameter.

        Resolution happens in two steps. First, only the most trustworthy tier
        that observed this parameter is considered -- a deterministic parser
        result is never diluted by an LLM guess about the same setting.

        Second, if several observations survive at that tier and they disagree,
        the riskier one wins, and every contributing line is merged into the
        evidence so the report shows why. Picking the safer reading would let a
        real exposure disappear behind a single reassuring line.
        """
        candidates = [f for f in self.facts if f.parameter == parameter]
        if not candidates:
            return None

        order = list(SourceType)
        best_tier = min(order.index(f.source_type) for f in candidates)
        tier = [f for f in candidates if order.index(f.source_type) == best_tier]
        if len(tier) == 1:
            return tier[0]

        winner = tier[0]
        for other in tier[1:]:
            if riskier(parameter, winner.value, other.value) != winner.value:
                winner = other

        merged_evidence: list[Evidence] = []
        for fact in tier:
            for item in fact.evidence:
                if item not in merged_evidence:
                    merged_evidence.append(item)

        return winner.model_copy(
            update={
                "evidence": sorted(merged_evidence, key=lambda e: e.line_number),
                "confidence": min(f.confidence for f in tier),
                "requires_review": any(f.requires_review for f in tier),
            }
        )

    def as_dict(self) -> dict[str, Any]:
        """Flatten to `{parameter: value}` for quick inspection and debugging."""
        return {p: f.value for p in {f.parameter for f in self.facts} if (f := self.get(p))}
