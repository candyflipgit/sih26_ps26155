"""The generic, vendor-agnostic parsing engine.

One engine drives every vendor. It walks a configuration line by line,
maintains the enclosing block context according to the vendor's declared block
style, canonicalises each line, and looks for a matching rule in the vendor's
rule pack.

Lines that match nothing are not errors -- they become `UnknownCommand` entries
that feed the Teach-AI queue, which is where the AI layer earns its place.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator

from app.ai.canonicalize import apply_value_rule, canonicalize
from app.parsers.rulepack import BlockStyle, MappingRule, RulePack
from app.schema.normalized import (
    DeviceIdentity,
    Evidence,
    NormalizationStats,
    NormalizedConfig,
    NormalizedFact,
    SourceType,
    UnknownCommand,
)
from app.schema.parameters import coerce_value

# Structural tokens that carry no security meaning on their own. Counting them
# as "uninterpreted" would understate coverage, so they are skipped entirely.
_STRUCTURAL = {
    "!", "end", "exit", "next", "quit", "return", "{", "}", "", "configure terminal",
    "config terminal", "commit", "top",
}

# Tokens that mark a line as bearing on the security posture of the device.
#
# A running configuration is mostly VLAN definitions, interface descriptions and
# routing statements. Those are not security controls, and treating them as
# "uninterpreted" would do two bad things: understate coverage, and bury the
# Teach-AI queue under noise an administrator has no reason to classify. Only
# lines touching one of these concepts are considered in scope.
_SECURITY_TOKENS = frozenset({
    "aaa", "access-class", "access-list", "acl", "admin", "auth", "authentication",
    "banner", "cipher", "community", "crypto", "encryption", "exec-timeout", "firewall",
    "http", "https", "idle-timeout", "kex", "key", "ldap", "log", "logging", "login",
    "motd", "ntp", "passwd", "password", "privilege", "radius", "secret", "service",
    "session", "snmp", "ssh", "ssl", "tacacs", "telnet", "timeout", "tls", "trusted",
    "user", "username", "vty", "web-management", "wheel",
})

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_WS_FLAT = re.compile(r"\s+")


def is_security_relevant(canonical: str, context: str = "") -> bool:
    """Whether a line plausibly encodes a security control.

    Deliberately generous: a false positive here only means an administrator
    sees one extra line in the Teach-AI queue, whereas a false negative means a
    genuine control is silently ignored.
    """
    tokens = set(_TOKEN_SPLIT.split(f"{canonical} {context}".lower()))
    return bool(tokens & _SECURITY_TOKENS)


class ParsedLine:
    """A significant configuration line together with its enclosing context."""

    __slots__ = ("number", "raw", "canonical", "flat", "slots", "context", "is_block_header")

    def __init__(
        self,
        number: int,
        raw: str,
        canonical: str,
        slots: list[str],
        context: str,
        is_block_header: bool = False,
    ):
        self.number = number
        self.raw = raw
        self.canonical = canonical
        # Whitespace-collapsed, lower-cased original. Canonicalisation hides
        # literal values behind placeholders -- `set name "public"` becomes
        # `set name <QUOTED>` -- so a regex rule that needs to see the value
        # itself is matched against this form as well.
        self.flat = _WS_FLAT.sub(" ", raw.strip()).lower()
        self.slots = slots
        self.context = context
        # A line that merely opens a block (`line vty 0 4`, `interface Gi1/0/1`)
        # states no policy by itself, so it must not reach the Teach-AI queue.
        self.is_block_header = is_block_header

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<L{self.number} {self.canonical!r} ctx={self.context!r}>"


def _is_comment(text: str, prefixes: Iterable[str]) -> bool:
    stripped = text.strip()
    return any(stripped.startswith(p) for p in prefixes)


def iter_significant_lines(config: str, pack: RulePack) -> Iterator[ParsedLine]:
    """Yield significant lines with block context resolved for the vendor."""
    style = pack.block_style
    indent_stack: list[tuple[int, str]] = []
    block_stack: list[str] = []
    key_path = ""

    # Materialise the significant lines up front. Indent-structured vendors need
    # one line of lookahead to tell a block header from a setting.
    candidates: list[tuple[int, str, str, int]] = []
    for number, raw in enumerate(config.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or _is_comment(stripped, pack.comment_prefixes):
            continue
        candidates.append((number, raw, stripped, len(raw) - len(raw.lstrip())))

    for position, (number, raw, stripped, indent) in enumerate(candidates):
        lowered = stripped.lower()

        # --- resolve context before deciding whether the line is structural,
        # because structural lines are exactly what push and pop the context.
        is_header = False

        if style is BlockStyle.INDENT:
            while indent_stack and indent_stack[-1][0] >= indent:
                indent_stack.pop()
            context = " / ".join(text for _, text in indent_stack)
            if lowered not in _STRUCTURAL:
                indent_stack.append((indent, lowered))
            # If the following line is indented further, this one opens a block.
            if position + 1 < len(candidates) and candidates[position + 1][3] > indent:
                is_header = True

        elif style is BlockStyle.CONFIG_END:
            if lowered.startswith(("config ", "edit ")):
                block_stack.append(lowered)
                continue
            if lowered in ("end", "next"):
                if block_stack:
                    block_stack.pop()
                continue
            context = " / ".join(block_stack)

        elif style is BlockStyle.KEY_PATH:
            if stripped.startswith("/"):
                # RouterOS: "/ip ssh set x=y" carries its own path inline, while
                # a bare "/ip ssh" line sets the path for the lines that follow.
                head, _, tail = stripped.partition(" set ")
                if not tail:
                    key_path = lowered
                    continue
                key_path = head.lower()
            context = key_path

        else:  # FLAT_SET -- Junos set-format lines are fully qualified already
            context = ""

        if lowered in _STRUCTURAL:
            continue

        canonical, slots = canonicalize(stripped)
        if not canonical:
            continue

        yield ParsedLine(number, stripped, canonical, slots, context, is_header)


def _rule_matches(rule: MappingRule, line: ParsedLine) -> tuple[bool, list[str]]:
    """Test one rule against one line, returning match status and value slots."""
    if rule.context and rule.context.lower() not in line.context.lower():
        return False, []

    if rule.template is not None:
        if rule.template.lower() == line.canonical.lower():
            return True, line.slots
        return False, []

    pattern = rule.compiled
    assert pattern is not None  # guaranteed by MappingRule validation
    # Try the canonical form first so a rule can key off placeholders such as
    # <IP>, then fall back to the flattened original so a rule can key off a
    # literal value that canonicalisation would have masked.
    match = pattern.search(line.canonical) or pattern.search(line.flat)
    if match is None:
        return False, []
    # Regex rules feed their capture groups in as slots.
    return True, [g for g in match.groups() if g is not None]


def extract_identity(config: str, pack: RulePack) -> DeviceIdentity:
    """Pull hostname, model, OS version and serial number out of the config."""
    identity = DeviceIdentity(vendor=pack.vendor, os_family=pack.os_family or None)
    for rule in pack.identity:
        match = rule.compiled.search(config)
        if match is None:
            continue
        # Identity patterns use alternation to cover the several places a vendor
        # prints the same detail, so take the first group that actually matched.
        captured = next((g for g in match.groups() if g), None) if match.groups() else match.group(0)
        if not captured:
            continue
        value = captured.strip()
        # Never let a later, vaguer pattern overwrite a value already found.
        if value and hasattr(identity, rule.field) and getattr(identity, rule.field) in (None, ""):
            setattr(identity, rule.field, value)
    return identity


def parse(config: str, pack: RulePack) -> NormalizedConfig:
    """Parse a configuration into the vendor-neutral Security Baseline Model."""
    facts: list[NormalizedFact] = []
    unknowns: list[UnknownCommand] = []
    interpreted = 0
    significant = 0

    rules = pack.rules
    ignore = pack.ignore_patterns

    for line in iter_significant_lines(config, pack):
        muted = any(p.search(line.canonical) or p.search(line.flat) for p in ignore)
        relevant = not line.is_block_header and is_security_relevant(line.canonical, line.context)

        # One line can legitimately assert several parameters: Cisco's
        # `transport input telnet ssh` says something about both protocols. So
        # scan every rule, but let only the first rule to claim a given
        # parameter win, since packs are ordered most specific first.
        claimed: set[str] = set()

        for rule in rules:
            if rule.parameter in claimed:
                continue
            ok, slots = _rule_matches(rule, line)
            if not ok:
                continue
            try:
                raw_value = apply_value_rule(rule.value_rule, slots)
                value = coerce_value(rule.parameter, raw_value)
            except ValueError:
                # A malformed rule must never take down a scan; the line simply
                # stays uninterpreted and surfaces for review.
                continue

            facts.append(
                NormalizedFact(
                    parameter=rule.parameter,
                    value=value,
                    confidence=1.0,
                    source_type=(
                        SourceType.KNOWLEDGE_BASE
                        if rule.origin.value == "learned"
                        else SourceType.DETERMINISTIC_PARSER
                    ),
                    evidence=[Evidence(line_number=line.number, text=line.raw)],
                    rationale=rule.description or None,
                )
            )
            claimed.add(rule.parameter)

        if claimed:
            # A line that yielded a fact counts towards coverage even if it is
            # on the ignore list, since the ignore list exists only to keep
            # uninterpretable plumbing out of the administrator's queue.
            if relevant:
                significant += 1
                interpreted += 1
        elif relevant and not muted:
            significant += 1
            unknowns.append(
                UnknownCommand(
                    raw=line.raw,
                    canonical=line.canonical,
                    line_number=line.number,
                    vendor_hint=pack.vendor,
                    context=line.context,
                )
            )

    produced = {f.parameter for f in facts}
    for default in pack.defaults:
        if default.parameter in produced:
            continue
        facts.append(
            NormalizedFact(
                parameter=default.parameter,
                value=coerce_value(default.parameter, default.value),
                confidence=1.0,
                source_type=SourceType.DETERMINISTIC_PARSER,
                evidence=[],
                rationale=default.rationale,
            )
        )

    by_source: dict[str, int] = {}
    for fact in facts:
        by_source[fact.source_type.value] = by_source.get(fact.source_type.value, 0) + 1

    return NormalizedConfig(
        device=extract_identity(config, pack),
        facts=facts,
        unknown_commands=unknowns,
        stats=NormalizationStats(
            total_lines=len(config.splitlines()),
            significant_lines=significant,
            interpreted_lines=interpreted,
            unknown_lines=len(unknowns),
            facts_by_source=by_source,
        ),
    )
