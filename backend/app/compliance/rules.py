"""The compliance rule catalogue.

One rule, many frameworks. A control such as "Telnet must be disabled" is a
single entry carrying its mappings to CIS, NIST SP 800-53, DISA STIG and
ISO/IEC 27001 side by side, rather than being duplicated into four catalogues
that then drift apart.

Honesty note, which belongs in the report as much as in the code: these are
control-family references compiled for this prototype to show that one
normalised model can be judged against several frameworks. They are not a
certified crosswalk, and this project does not reproduce the copyrighted text of
any benchmark.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.schema.parameters import PARAMETER_INDEX


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}[self.value]

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[self.value]


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # The parser could not determine the setting. Deliberately distinct from
    # FAIL: reporting "we could not tell" as a violation manufactures false
    # positives and destroys trust in the score.
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Operator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN = "in"
    NOT_IN = "not_in"
    # Passes when the parameter was observed at all, whatever its value.
    EXISTS = "exists"


class ComplianceRule(BaseModel):
    """A single, deterministically evaluable security control."""

    id: str
    title: str
    parameter: str
    operator: Operator
    expected: Any = None
    severity: Severity
    description: str
    # Plain-language explanation of the risk, shown in the UI and the report.
    impact: str = ""
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    remediation_id: str | None = None
    # Rules are versioned so a finding can record which revision judged it.
    version: str = "1.0"
    # An integer parameter value that means "unset"/"never", handled explicitly
    # rather than relying on numeric ordering.
    sentinel: int | None = None
    sentinel_status: Status = Status.FAIL

    @model_validator(mode="after")
    def _check(self) -> ComplianceRule:
        if self.parameter not in PARAMETER_INDEX:
            raise ValueError(f"rule {self.id}: '{self.parameter}' is not a canonical parameter")
        if self.operator is not Operator.EXISTS and self.expected is None:
            raise ValueError(f"rule {self.id}: operator '{self.operator.value}' needs an expected value")
        return self

    def applies_to(self, framework: str | None) -> bool:
        if framework is None or framework.upper() == "ALL":
            return True
        return framework.upper() in {k.upper() for k in self.frameworks}

    def references(self, framework: str | None) -> list[str]:
        if framework is None or framework.upper() == "ALL":
            return [f"{k} {ref}" for k, refs in self.frameworks.items() for ref in refs]
        for key, refs in self.frameworks.items():
            if key.upper() == framework.upper():
                return refs
        return []


class FrameworkInfo(BaseModel):
    key: str
    name: str
    publisher: str
    note: str = ""


class RuleCatalog(BaseModel):
    """The full set of controls plus framework metadata."""

    version: str = "1.0"
    frameworks: list[FrameworkInfo] = Field(default_factory=list)
    rules: list[ComplianceRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> RuleCatalog:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return self

    @classmethod
    def load(cls, path: Path) -> RuleCatalog:
        return cls.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))

    def for_framework(self, framework: str | None) -> list[ComplianceRule]:
        return [r for r in self.rules if r.applies_to(framework)]

    def get(self, rule_id: str) -> ComplianceRule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    @property
    def framework_keys(self) -> list[str]:
        return [f.key for f in self.frameworks]
