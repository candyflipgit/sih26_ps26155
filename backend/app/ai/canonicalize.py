"""Command canonicalisation: turn a config line into a reusable template.

A knowledge-base entry should not be a literal string. If an administrator
teaches the system that

    ip ssh version 2   ->  management.ssh.version = 2

then the system has learned the *shape* of the command, and must also recognise

    ip ssh version 1   ->  management.ssh.version = 1

Canonicalisation replaces the variable parts of a line with typed placeholders
and returns the captured values as ordered slots. The template is the lookup
key; the slots supply the value. This is deterministic, instant, and works with
no LLM at all -- which is why it is the tier that carries the demo.
"""

from __future__ import annotations

import re

# Order matters: IPv4 must be consumed before bare integers, or 10.0.0.1
# degrades into four separate <NUM> tokens.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("<IPV6>", re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)),
    ("<CIDR>", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")),
    ("<IP>", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("<MAC>", re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.I)),
    ("<QUOTED>", re.compile(r"\"[^\"]*\"|'[^']*'")),
    ("<HEX>", re.compile(r"\b0x[0-9a-f]+\b", re.I)),
    # Juniper spells protocol versions as a standalone v1/v2 token, so capture
    # it and let one template cover every version. The lookbehind keeps
    # hyphen-attached versions out: in FortiOS's `set admin-ssh-v1 disable` the
    # version is part of the setting name, and collapsing it would make
    # admin-ssh-v1 and admin-ssh-v2 indistinguishable.
    ("<VER>", re.compile(r"(?<![\w-])v(?=\d)\d+\b", re.I)),
    ("<NUM>", re.compile(r"(?<![\w.\-])\d+(?![\w.])")),
]

_WS = re.compile(r"\s+")


def canonicalize(line: str) -> tuple[str, list[str]]:
    """Return `(template, slots)` for a configuration line.

    >>> canonicalize("ip ssh version 2")
    ('ip ssh version <NUM>', ['2'])
    >>> canonicalize("  NTP   server   10.10.10.10 ")
    ('ntp server <IP>', ['10.10.10.10'])
    >>> canonicalize("exec-timeout 10 0")
    ('exec-timeout <NUM> <NUM>', ['10', '0'])
    """
    # Lower-case up front so the placeholders inserted below stay upper-case and
    # remain readable in the Teach-AI screen and the knowledge base.
    text = _WS.sub(" ", line.strip()).lower()
    if not text:
        return "", []

    # Record every match with its span first, so replacement does not disturb
    # the offsets used to order the captured slots.
    spans: list[tuple[int, int, str, str]] = []
    claimed: list[tuple[int, int]] = []

    for placeholder, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span()
            if any(start < ce and end > cs for cs, ce in claimed):
                continue  # already consumed by a higher-priority pattern
            claimed.append((start, end))
            spans.append((start, end, placeholder, m.group(0)))

    spans.sort(key=lambda s: s[0])

    out: list[str] = []
    slots: list[str] = []
    cursor = 0
    for start, end, placeholder, captured in spans:
        out.append(text[cursor:start])
        out.append(placeholder)
        slots.append(captured)
        cursor = end
    out.append(text[cursor:])

    template = _WS.sub(" ", "".join(out)).strip()
    return template, slots


# --- value extraction ------------------------------------------------------

_MINUTES = "minutes_to_seconds"
_NEGATE = "negate"
_DIGITS = "digits"


def apply_value_rule(rule: str, slots: list[str]) -> object:
    """Resolve a knowledge-base value rule against captured slots.

    Supported rules:
      ``literal:true`` / ``literal:false`` / ``literal:42``  -- fixed value
      ``slot:0``                                            -- captured slot N
      ``slot:0:minutes_to_seconds``                         -- slot N, transformed
      ``slot:0:negate``                                     -- boolean slot, inverted
      ``slot:0:digits``                                     -- strip non-digits ("v2" -> 2)
    """
    kind, _, rest = rule.partition(":")

    if kind == "literal":
        lowered = rest.strip().lower()
        if lowered in ("true", "false"):
            return lowered == "true"
        try:
            return int(rest)
        except ValueError:
            return rest

    if kind == "slot":
        index_str, _, transform = rest.partition(":")
        index = int(index_str)
        if index >= len(slots):
            raise ValueError(f"value rule '{rule}' wants slot {index}, only {len(slots)} captured")
        raw = slots[index]

        if transform == _MINUTES:
            return int(raw) * 60
        if transform == _DIGITS:
            digits = "".join(ch for ch in raw if ch.isdigit())
            if not digits:
                raise ValueError(f"value rule '{rule}': no digits in {raw!r}")
            return int(digits)
        if transform == _NEGATE:
            return raw.strip().lower() not in ("yes", "true", "enable", "enabled", "1")
        return raw

    raise ValueError(f"unrecognised value rule: {rule!r}")


def template_similarity(a: str, b: str) -> float:
    """Cheap token-level Jaccard similarity between two templates.

    Used only as a tie-breaker when selecting few-shot examples for the LLM.
    Deliberately not used to make a mapping decision on its own -- measurement
    showed similarity scores on CLI text are not separable enough to trust.
    """
    ta, tb = set(a.split()), set(b.split())
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)
