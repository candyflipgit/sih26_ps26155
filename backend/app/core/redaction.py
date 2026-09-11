"""Secret redaction for configuration text.

A device configuration is one of the most credential-dense files an
organisation holds: privileged password hashes, SNMP communities, pre-shared
keys, RADIUS secrets, private keys. Two places must never receive those values.

  * The LLM prompt. Sending them to an inference endpoint would disclose live
    credentials to a third party for no analytical benefit -- the model needs
    the *shape* of a command, never the secret in it.
  * The generated report, which is emailed and filed far more widely than the
    configuration ever was.

Redaction deliberately preserves the surrounding command structure. Replacing
the whole line would destroy the evidence trail; replacing only the secret keeps
`username admin password <REDACTED>` both safe and legible, and still lets the
parser conclude that a password is set.
"""

from __future__ import annotations

import re

MASK = "<REDACTED>"

# Words that follow a credential keyword but are themselves metadata -- a hash
# type, an encoding marker, an already-applied mask. Masking one of these would
# consume the substitution and leave the real secret exposed immediately after,
# so a match landing on one of them is skipped and the next rule gets its turn.
_METADATA = {
    "enc", "encrypted", "md5", "sha1", "sha256", "sha512", "aes", "des", "type",
    "value", "hash", "format", "level", "password", "secret", "key", MASK.lower(),
}

# Ordered most specific first. Each pattern keeps its leading group (the command
# context) and masks the trailing group (the secret itself).
_RULES: list[tuple[re.Pattern[str], str]] = [
    # Junos: encrypted-password "..." / plain-text-password-value "..."
    (re.compile(r"\b((?:encrypted-password|plain-text-password-value)\s+)(\"[^\"]*\"|\S+)", re.I),
     r"\1" + MASK),
    # FortiOS: `set password ENC <blob>`
    (re.compile(r"\b(set\s+password\s+ENC\s+)(\S+)", re.I), r"\1" + MASK),
    # Keyed authentication material, with an optional algorithm word between.
    (re.compile(
        r"\b((?:authentication-key|md5-key)\s+(?:\d+\s+)?(?:(?:type|value)\s+)?"
        r"(?:md5|sha1|sha256|sha512)?\s*)(\"[^\"]*\"|\S+)", re.I), r"\1" + MASK),
    # Shared secrets for AAA and VPN
    # The optional digit is Cisco's encoding-type marker, which belongs to the
    # command rather than to the secret that follows it.
    (re.compile(
        r"\b((?:pre-shared-key|shared-secret|tacacs-server\s+key|radius-server\s+key)\s+"
        r"(?:\d+\s+)?)(\"[^\"]*\"|\S+)", re.I), r"\1" + MASK),
    # SNMP community strings, including Junos `set snmp community <name>`
    (re.compile(r"\b((?:snmp-server\s+community|set\s+snmp\s+community)\s+)(\S+)", re.I),
     r"\1" + MASK),
    # key=value forms, e.g. RouterOS `password=Str0ng`
    (re.compile(r"\b((?:password|passwd|secret|key|community)\s*=\s*)(\"[^\"]*\"|\S+)", re.I),
     r"\1" + MASK),
    # A bare `key <value>`, as in `crypto isakmp key ...` or `key-string ...`.
    # The lookahead spares the words that follow `key` structurally rather than
    # introducing a secret, such as `key chain` or `key length`.
    (re.compile(
        r"\b((?:key-string|key)\s+(?:\d+\s+)?)"
        r"(?!chain\b|id\b|length\b|size\b|exchange\b|type\b|lifetime\b)"
        r"(\"[^\"]*\"|\S+)", re.I), r"\1" + MASK),
    # Cisco style: `password 7 104D000A`, `secret 9 $9$...`, `enable secret ...`
    (re.compile(r"\b((?:password|secret)\s+(?:\d\s+)?)(\"[^\"]*\"|\S+)", re.I), r"\1" + MASK),
    # Anything that looks like a hash blob, wherever it appears
    (re.compile(r"\$[0-9a-z]{1,3}\$[^\s\"']{8,}", re.I), MASK),
]

# Multi-line blocks that are replaced wholesale.
_BLOCKS = [
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.S | re.I,
    ),
    re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S | re.I),
]

# Community strings that carry no secrecy and are worth keeping visible, since
# the whole point of the finding is that they are the well-known defaults.
_KEEP = {"public", "private"}


def redact(text: str) -> tuple[str, int]:
    """Mask credentials in configuration text.

    Returns the redacted text and the number of substitutions made, so the UI
    and report can state plainly how many secrets were withheld.
    """
    count = 0

    for pattern in _BLOCKS:
        text, n = pattern.subn(f"{MASK} (key material removed)", text)
        count += n

    for pattern, replacement in _RULES:
        def _sub(match: re.Match[str]) -> str:
            nonlocal count
            if match.lastindex and match.lastindex >= 2:
                candidate = match.group(2).strip("\"'").lower()
                # A well-known default community is the evidence for its own
                # finding, so masking it would hide the very thing reported.
                if candidate in _KEEP:
                    return match.group(0)
                # Never spend the substitution on a metadata word; leaving the
                # match alone lets a later, more specific rule reach the secret.
                if candidate in _METADATA:
                    return match.group(0)
            count += 1
            return match.expand(replacement)

        text = pattern.sub(_sub, text)

    return text, count


def redact_line(line: str) -> str:
    """Redact a single line, for evidence shown in reports and the UI."""
    return redact(line)[0]
