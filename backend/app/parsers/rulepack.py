"""Vendor rule packs: parsing knowledge expressed as data, not code.

A rule pack is a JSON document describing how one vendor's CLI maps onto the
canonical parameter registry. Nothing about a vendor lives in Python -- adding
Arista or MikroTik means dropping in a new JSON file, which is what makes the
"support a new vendor without a backend redeployment" requirement literally
true rather than aspirational.

Crucially, a rule an administrator teaches through the Teach-AI screen is the
same `MappingRule` shape as one that shipped in the box. Learned knowledge is
not a second-class side table; it merges into the same pack.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.schema.parameters import PARAMETER_INDEX


class BlockStyle(str, Enum):
    """How a vendor delimits nested configuration context."""

    INDENT = "indent"          # Cisco IOS: indentation implies parentage
    FLAT_SET = "flat_set"      # Junos set-format: every line is fully qualified
    CONFIG_END = "config_end"  # FortiOS: config/edit ... next/end
    KEY_PATH = "key_path"      # RouterOS: /path then settings


class RuleOrigin(str, Enum):
    BUILTIN = "builtin"        # shipped in the rule pack
    LEARNED = "learned"        # taught by an administrator via Teach-AI


class MappingRule(BaseModel):
    """One CLI construct mapped to one canonical parameter."""

    id: str
    parameter: str
    value_rule: str
    # Exactly one matcher must be supplied.
    template: str | None = None   # exact canonicalised match, generalises via slots
    regex: str | None = None      # fallback for messier syntax; matched on the canonical line
    # Optional substring that must appear in the enclosing context chain.
    context: str | None = None
    description: str = ""
    origin: RuleOrigin = RuleOrigin.BUILTIN
    # Learned rules carry provenance for the audit trail.
    approved_by: str | None = None
    approved_at: str | None = None

    @model_validator(mode="after")
    def _check(self) -> MappingRule:
        if bool(self.template) == bool(self.regex):
            raise ValueError(f"rule {self.id}: supply exactly one of 'template' or 'regex'")
        if self.parameter not in PARAMETER_INDEX:
            raise ValueError(f"rule {self.id}: '{self.parameter}' is not a canonical parameter")
        return self

    @property
    def compiled(self) -> re.Pattern[str] | None:
        if self.regex is None:
            return None
        return re.compile(self.regex, re.I)


class DefaultAssertion(BaseModel):
    """A fact asserted only when no rule produced that parameter.

    Absence carries meaning in network configuration: a Cisco config with no
    `ntp server` line has NTP disabled. Without these, every unconfigured
    control would evaluate as UNKNOWN and the compliance score would be
    meaningless.
    """

    parameter: str
    value: Any
    rationale: str

    @model_validator(mode="after")
    def _check(self) -> DefaultAssertion:
        if self.parameter not in PARAMETER_INDEX:
            raise ValueError(f"default: '{self.parameter}' is not a canonical parameter")
        return self


class IdentityRule(BaseModel):
    """Extracts device identification from the configuration."""

    field: str  # hostname | os_version | model | serial_number
    regex: str

    @property
    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex, re.I | re.M)


class RulePack(BaseModel):
    """Everything the engine needs to parse one vendor."""

    vendor: str
    display_name: str
    os_family: str = ""
    block_style: BlockStyle = BlockStyle.FLAT_SET
    # Signature tokens used by the vendor detector, weighted by distinctiveness.
    signatures: dict[str, float] = Field(default_factory=dict)
    comment_prefixes: list[str] = Field(default_factory=lambda: ["!", "#"])
    identity: list[IdentityRule] = Field(default_factory=list)
    rules: list[MappingRule] = Field(default_factory=list)
    defaults: list[DefaultAssertion] = Field(default_factory=list)
    # Lines that sit inside a security-related block but state no policy of
    # their own. FortiOS is the clearest case: everything under `config system
    # admin` looks relevant by context, yet `set vdom "root"` is plumbing. Left
    # unfiltered these bury the Teach-AI queue and understate coverage.
    ignore: list[str] = Field(default_factory=list)

    @property
    def ignore_patterns(self) -> list[re.Pattern[str]]:
        return [re.compile(p, re.I) for p in self.ignore]

    @model_validator(mode="after")
    def _unique_ids(self) -> RulePack:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"{self.vendor}: duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        return self

    @property
    def builtin_rules(self) -> list[MappingRule]:
        return [r for r in self.rules if r.origin is RuleOrigin.BUILTIN]

    @property
    def learned_rules(self) -> list[MappingRule]:
        return [r for r in self.rules if r.origin is RuleOrigin.LEARNED]


class RulePackLibrary:
    """Loads and holds every vendor rule pack, plus learned additions."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self._packs: dict[str, RulePack] = {}
        self.reload()

    def reload(self) -> None:
        """Re-read every pack from disk.

        Called after an administrator approves a mapping, which is what lets
        newly taught knowledge take effect without restarting the process.
        """
        packs: dict[str, RulePack] = {}
        for path in sorted(self.directory.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            pack = RulePack.model_validate(data)
            packs[pack.vendor] = pack
        self._packs = packs

    def get(self, vendor: str) -> RulePack | None:
        return self._packs.get(vendor)

    def all(self) -> list[RulePack]:
        return list(self._packs.values())

    @property
    def vendors(self) -> list[str]:
        return list(self._packs)

    def path_for(self, vendor: str) -> Path:
        return self.directory / f"{vendor}.json"

    def add_learned_rule(self, vendor: str, rule: MappingRule) -> None:
        """Persist an administrator-approved mapping into the vendor's pack.

        Writes through to disk and reloads, so the very next analysis run
        recognises the command. This is the mechanism behind the training loop.
        """
        pack = self._packs.get(vendor)
        if pack is None:
            raise KeyError(f"no rule pack for vendor {vendor!r}")

        rule.origin = RuleOrigin.LEARNED
        pack.rules.append(rule)

        path = self.path_for(vendor)
        path.write_text(
            json.dumps(pack.model_dump(mode="json", exclude_none=True), indent=2),
            encoding="utf-8",
        )
        self.reload()
