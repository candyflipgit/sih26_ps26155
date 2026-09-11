"""Redaction must never let a live credential through.

These are the highest-consequence tests in the suite: a miss here means a real
password is transmitted to an inference endpoint or printed into a report that
gets emailed around.
"""

from __future__ import annotations

import pytest

from app.core.redaction import MASK, redact, redact_line

# (line, the substring that must not survive)
SECRET_LINES = [
    ("enable secret 9 $9$vFxSj0jK$fB1cWq8xN4pRt7YvZ2sD6hLmK9nQ3wXe", "fB1cWq8x"),
    ("username admin privilege 15 password 7 104D000A0618", "104D000A0618"),
    ("username admin password 0 PlainTextPass99", "PlainTextPass99"),
    ('set system login user a authentication plain-text-password-value "Password123"', "Password123"),
    ('set system root-authentication encrypted-password "$6$Kx8Tn2vQ$8fJqL3mNpR"', "8fJqL3mNpR"),
    ("set password ENC SH2Kx8Tn2vQ8fJqL3mNpR7sV1wX4yZ6aB9cD2eF5gH8iJ0kL3mN", "SH2Kx8Tn2vQ"),
    ("/user add name=netops group=full password=Str0ngP@ssPhrase2026", "Str0ngP@ssPhrase2026"),
    ("snmp-server community s3cr3tRW RW", "s3cr3tRW"),
    ("ntp authentication-key 1 md5 MyNtpKey123", "MyNtpKey123"),
    ("tacacs-server key 7 08351F1B0D", "08351F1B0D"),
    ("radius-server key MySharedSecret", "MySharedSecret"),
    ("crypto isakmp key MyPreShared address 0.0.0.0", "MyPreShared"),
]


@pytest.mark.parametrize("line,secret", SECRET_LINES)
def test_secret_never_survives_redaction(line: str, secret: str) -> None:
    assert secret not in redact_line(line)


@pytest.mark.parametrize("line,secret", SECRET_LINES)
def test_command_structure_survives_redaction(line: str, secret: str) -> None:
    """The evidence trail is worthless if the whole line is destroyed."""
    redacted = redact_line(line)
    assert MASK in redacted
    assert redacted.split()[0] == line.split()[0]


@pytest.mark.parametrize(
    "line",
    [
        "ip ssh version 2",
        "transport input telnet",
        "no ip http server",
        "ntp server 10.50.4.10",
        "set allowaccess ping https ssh",
    ],
)
def test_benign_configuration_is_untouched(line: str) -> None:
    assert redact_line(line) == line


def test_default_communities_stay_visible() -> None:
    """A default community is the evidence for its own finding."""
    assert redact_line("snmp-server community public RO") == "snmp-server community public RO"
    assert "private" in redact_line("snmp-server community private RW")


def test_private_key_block_is_removed() -> None:
    text = (
        "crypto pki certificate chain TP\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxyz123SECRETKEYMATERIAL\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    redacted, count = redact(text)
    assert "SECRETKEYMATERIAL" not in redacted
    assert count >= 1


def test_redaction_counts_are_reported() -> None:
    text = "\n".join(line for line, _ in SECRET_LINES)
    _, count = redact(text)
    assert count >= len(SECRET_LINES) - 1


def test_redaction_is_idempotent() -> None:
    once, _ = redact("username admin password 7 104D000A0618")
    twice, _ = redact(once)
    assert once == twice
