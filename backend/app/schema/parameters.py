"""Canonical vendor-neutral security parameter registry.

This module is the single source of truth for the Security Baseline Model.
Everything downstream reads from it:

  * vendor parsers emit facts keyed by these parameter names
  * the compliance rule catalog references these parameter names
  * the LLM prompt enumerates them as the *only* allowed output vocabulary
  * the Teach-AI dropdown is populated from them

Keeping it as data rather than scattered string literals is what makes adding
a vendor a content change instead of a code change.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class ValueType(str, Enum):
    BOOLEAN = "boolean"
    INTEGER = "integer"
    STRING = "string"
    STRING_LIST = "string_list"


class Category(str, Enum):
    MANAGEMENT = "Management Plane"
    AUTHENTICATION = "Authentication and Accounts"
    LOGGING = "Logging and Monitoring"
    TIME = "Time Synchronisation"
    SNMP = "SNMP"
    ACCESS = "Access Control"
    SERVICES = "Insecure Services"


class ParameterDef(BaseModel):
    """Definition of one canonical security parameter."""

    name: str
    category: Category
    value_type: ValueType
    description: str
    # Human-readable hint shown in the Teach-AI UI and given to the LLM.
    guidance: str = ""


def _p(
    name: str,
    category: Category,
    vt: ValueType,
    desc: str,
    guidance: str = "",
) -> ParameterDef:
    return ParameterDef(
        name=name,
        category=category,
        value_type=vt,
        description=desc,
        guidance=guidance,
    )


PARAMETERS: list[ParameterDef] = [
    # ---- Management plane -------------------------------------------------
    _p("management.ssh.enabled", Category.MANAGEMENT, ValueType.BOOLEAN,
       "SSH management access is enabled",
       "True when the device accepts SSH for administrative access."),
    _p("management.ssh.version", Category.MANAGEMENT, ValueType.INTEGER,
       "Negotiated SSH protocol version",
       "Use 2 when only SSHv2 is permitted, 1 when SSHv1 is still allowed."),
    _p("management.ssh.strong_crypto", Category.MANAGEMENT, ValueType.BOOLEAN,
       "SSH restricted to strong ciphers and key exchange",
       "True when weak ciphers such as 3des, cbc modes or sha1 kex are disabled."),
    _p("management.telnet.enabled", Category.MANAGEMENT, ValueType.BOOLEAN,
       "Telnet management access is enabled",
       "True if any VTY line or service accepts Telnet. Cleartext protocol."),
    _p("management.http.enabled", Category.MANAGEMENT, ValueType.BOOLEAN,
       "Plaintext HTTP management server is enabled",
       "True when an unencrypted web admin interface is listening."),
    _p("management.https.enabled", Category.MANAGEMENT, ValueType.BOOLEAN,
       "HTTPS management server is enabled",
       "True when the encrypted web admin interface is listening."),

    # ---- Authentication ---------------------------------------------------
    _p("authentication.password.min_length", Category.AUTHENTICATION, ValueType.INTEGER,
       "Minimum enforced password length",
       "Integer count of characters required by the password policy."),
    _p("authentication.password.encryption_enabled", Category.AUTHENTICATION, ValueType.BOOLEAN,
       "Stored passwords are encrypted or hashed",
       "True when plaintext passwords are not written to the configuration."),
    _p("authentication.privileged.protected", Category.AUTHENTICATION, ValueType.BOOLEAN,
       "Privileged or enable mode requires a strong secret",
       "True when privileged escalation is protected by a hashed secret."),
    _p("authentication.aaa.enabled", Category.AUTHENTICATION, ValueType.BOOLEAN,
       "Centralised AAA is configured",
       "True when TACACS+, RADIUS or equivalent AAA authentication is in use."),
    _p("authentication.default_accounts.present", Category.AUTHENTICATION, ValueType.BOOLEAN,
       "Default or well-known accounts still exist",
       "True when accounts such as admin, cisco or root remain configured."),

    # ---- Logging ----------------------------------------------------------
    _p("logging.local.enabled", Category.LOGGING, ValueType.BOOLEAN,
       "Local or buffered logging is enabled",
       "True when the device retains logs locally."),
    _p("logging.remote_syslog.enabled", Category.LOGGING, ValueType.BOOLEAN,
       "Logs are shipped to a remote syslog collector",
       "True when at least one external log host is configured."),
    _p("logging.admin_actions.enabled", Category.LOGGING, ValueType.BOOLEAN,
       "Administrative and configuration changes are logged",
       "True when command or configuration change accounting is enabled."),

    # ---- Time -------------------------------------------------------------
    _p("time.ntp.enabled", Category.TIME, ValueType.BOOLEAN,
       "NTP time synchronisation is configured",
       "True when at least one NTP server is configured."),
    _p("time.ntp.authenticated", Category.TIME, ValueType.BOOLEAN,
       "NTP peers are cryptographically authenticated",
       "True when NTP authentication keys are configured and trusted."),

    # ---- SNMP -------------------------------------------------------------
    _p("snmp.enabled", Category.SNMP, ValueType.BOOLEAN,
       "SNMP agent is enabled",
       "True when the SNMP agent is running."),
    _p("snmp.insecure_version_enabled", Category.SNMP, ValueType.BOOLEAN,
       "SNMP v1 or v2c community based access is enabled",
       "True when SNMPv1 or v2c is permitted. These carry communities in cleartext."),
    _p("snmp.default_community.present", Category.SNMP, ValueType.BOOLEAN,
       "Default community strings are in use",
       "True when well-known communities such as public or private are configured."),

    # ---- Access control ---------------------------------------------------
    _p("access.management_acl.enabled", Category.ACCESS, ValueType.BOOLEAN,
       "Management access is restricted by ACL or trusted hosts",
       "True when admin access is limited to specific source networks."),
    _p("access.idle_timeout.seconds", Category.ACCESS, ValueType.INTEGER,
       "Idle administrative session timeout, in seconds",
       "Convert minutes to seconds. Zero means sessions never time out."),
    _p("access.login_banner.present", Category.ACCESS, ValueType.BOOLEAN,
       "A legal login banner is configured",
       "True when a banner or MOTD warning is presented before login."),

    # ---- Insecure services ------------------------------------------------
    _p("services.source_routing.enabled", Category.SERVICES, ValueType.BOOLEAN,
       "IP source routing is enabled",
       "True when source-routed packets are accepted."),
    _p("services.insecure_smallservers.enabled", Category.SERVICES, ValueType.BOOLEAN,
       "Legacy TCP or UDP small servers are enabled",
       "True when echo, chargen or discard style services are running."),
]


PARAMETER_INDEX: dict[str, ParameterDef] = {p.name: p for p in PARAMETERS}


# --- risk direction --------------------------------------------------------
#
# A configuration can assert the same parameter more than once, and the
# assertions can disagree. A device with two VTY ranges may permit Telnet on one
# and SSH-only on the other; whichever line the parser happened to see first
# must not decide the verdict.
#
# The resolution rule is to keep the *riskier* observation. In a security audit
# a false negative (missing a real exposure) is far more damaging than a false
# positive (flagging something an administrator can dismiss with evidence in
# hand). This table declares, per parameter, which direction is the risky one.

RISKY_WHEN: dict[str, str] = {
    # booleans where True is the exposure
    "management.telnet.enabled": "true",
    "management.http.enabled": "true",
    "snmp.enabled": "true",
    "snmp.insecure_version_enabled": "true",
    "snmp.default_community.present": "true",
    "authentication.default_accounts.present": "true",
    "services.source_routing.enabled": "true",
    "services.insecure_smallservers.enabled": "true",
    # booleans where False is the exposure
    "management.ssh.enabled": "false",
    "management.ssh.strong_crypto": "false",
    "management.https.enabled": "false",
    "authentication.password.encryption_enabled": "false",
    "authentication.privileged.protected": "false",
    "authentication.aaa.enabled": "false",
    "logging.local.enabled": "false",
    "logging.remote_syslog.enabled": "false",
    "logging.admin_actions.enabled": "false",
    "time.ntp.enabled": "false",
    "time.ntp.authenticated": "false",
    "access.management_acl.enabled": "false",
    "access.login_banner.present": "false",
    # numerics: "low" means a smaller number is the weaker posture
    "management.ssh.version": "low",
    "authentication.password.min_length": "low",
    # A longer idle timeout leaves sessions open for longer, so "high" is risky.
    # Zero is the special case meaning "never expire"; the compliance rule for
    # this parameter treats 0 explicitly rather than relying on ordering.
    "access.idle_timeout.seconds": "high",
}


def riskier(parameter: str, a: Any, b: Any) -> Any:
    """Return whichever of two observed values represents the weaker posture."""
    direction = RISKY_WHEN.get(parameter)
    if direction is None or a == b:
        return a

    if direction in ("true", "false"):
        risky = direction == "true"
        return risky if risky in (a, b) else a

    if direction == "low":
        # 0 on a numeric security setting almost always means "unset", which is
        # weaker than any configured value.
        if 0 in (a, b):
            return 0
        return min(a, b)

    if direction == "high":
        if 0 in (a, b):
            return 0  # "never times out" is the worst case for a timeout
        return max(a, b)

    return a


def is_valid_parameter(name: str) -> bool:
    return name in PARAMETER_INDEX


def get_parameter(name: str) -> ParameterDef | None:
    return PARAMETER_INDEX.get(name)


_TRUTHY = {"true", "yes", "enabled", "enable", "on", "1"}
_FALSEY = {"false", "no", "disabled", "disable", "off", "0"}


def coerce_value(name: str, value: Any) -> Any:
    """Coerce a raw value onto the declared type for a parameter.

    Raises ValueError when the value cannot be represented. This is the guard
    that stops an LLM from writing "yes please" into a boolean field.
    """
    spec = PARAMETER_INDEX.get(name)
    if spec is None:
        raise ValueError(f"unknown parameter: {name}")

    if spec.value_type is ValueType.BOOLEAN:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in _TRUTHY:
                return True
            if lowered in _FALSEY:
                return False
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        raise ValueError(f"{name}: cannot coerce {value!r} to boolean")

    if spec.value_type is ValueType.INTEGER:
        if isinstance(value, bool):
            raise ValueError(f"{name}: boolean is not a valid integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            digits = "".join(ch for ch in value if ch.isdigit() or ch == "-")
            if digits not in ("", "-"):
                return int(digits)
        raise ValueError(f"{name}: cannot coerce {value!r} to integer")

    if spec.value_type is ValueType.STRING_LIST:
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return [value]
        raise ValueError(f"{name}: cannot coerce {value!r} to string list")

    return str(value)


def vocabulary_for_prompt() -> str:
    """Render the allowed parameter vocabulary for the LLM system prompt."""
    lines: list[str] = []
    current: str | None = None
    for spec in PARAMETERS:
        if spec.category.value != current:
            current = spec.category.value
            lines.append("")
            lines.append(f"# {current}")
        lines.append(
            f"- {spec.name} ({spec.value_type.value}): {spec.description}. {spec.guidance}"
        )
    return "\n".join(lines).strip()
