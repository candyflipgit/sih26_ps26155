"""Live configuration collection over SSH, via Netmiko.

The problem statement suggests Netmiko or NAPALM for data collection. Here that
is an optional front door rather than the critical path. Uploaded files remain
the primary input, deliberately: an auditor that needs standing credentials to
every device on the network is itself one of the most valuable targets on it.

Credential handling is the part worth reading closely. Credentials arrive per
request, are used for exactly one SSH session, and are never stored, logged, or
echoed back -- including in error messages, because a driver exception can carry
connection details. The password travels as a SecretStr so an accidental repr or
log line prints asterisks rather than the secret.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import SecretStr

logger = logging.getLogger(__name__)

# Rule-pack vendor -> (Netmiko platform, read-only commands). The commands are
# chosen so their combined output is exactly what that vendor's rule pack
# parses: identity from the version command, policy from the configuration.
PLATFORMS: dict[str, tuple[str, list[str]]] = {
    "cisco_ios": ("cisco_ios", ["show version", "show running-config"]),
    "juniper_junos": (
        "juniper_junos",
        ["show version", "show configuration | display set | no-more"],
    ),
    "fortinet_fortios": ("fortinet", ["get system status", "show full-configuration"]),
    "paloalto_panos": (
        "paloalto_panos",
        ["show system info", "set cli config-output-format set", "show config running"],
    ),
}

_HOST = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")


class CollectorUnavailable(RuntimeError):
    """Netmiko is not installed; live collection is an optional extra."""


class CollectionError(RuntimeError):
    """A collection attempt failed, with the HTTP status that best describes why."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Collection:
    text: str
    commands: list[str] = field(default_factory=list)
    duration_ms: float = 0.0


def netmiko_available() -> bool:
    try:
        import netmiko  # noqa: F401
    except ImportError:
        return False
    return True


def _driver_exceptions() -> tuple[tuple[type, ...], tuple[type, ...]]:
    try:
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError:
        return (), ()
    return (NetmikoAuthenticationException,), (NetmikoTimeoutException,)


def collect(
    host: str,
    platform: str,
    username: str,
    password: SecretStr,
    port: int = 22,
    timeout: float = 20.0,
    connect: Callable[..., Any] | None = None,
) -> Collection:
    """Open one SSH session, run the platform's read-only commands, close it.

    `connect` exists so the flow can be tested without a device; in normal use
    it is Netmiko's ConnectHandler.
    """
    if platform not in PLATFORMS:
        supported = ", ".join(sorted(PLATFORMS))
        raise CollectionError(f"unsupported platform {platform!r}; supported: {supported}", 422)
    if not _HOST.match(host or ""):
        raise CollectionError("host must be a hostname or an IP address", 422)
    if not username:
        raise CollectionError("username is required", 422)

    if connect is None:
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            raise CollectorUnavailable(
                "Live collection needs Netmiko: pip install -r backend/requirements-collect.txt"
            ) from exc
        connect = ConnectHandler

    auth_errors, timeout_errors = _driver_exceptions()
    device_type, commands = PLATFORMS[platform]
    started = time.perf_counter()
    session = None
    sections: list[str] = []

    try:
        session = connect(
            device_type=device_type,
            host=host,
            port=port,
            username=username,
            password=password.get_secret_value(),
            timeout=timeout,
            conn_timeout=timeout,
        )
        for command in commands:
            output = session.send_command(command, read_timeout=timeout * 3)
            sections.append(f"# {command}\n{output}")
    except CollectionError:
        raise
    except auth_errors:
        raise CollectionError(f"authentication to {host} failed", 401) from None
    except timeout_errors:
        raise CollectionError(f"{host}:{port} did not respond within {timeout:.0f}s", 504) from None
    except Exception as exc:
        # Deliberately generic. A driver exception can echo connection details,
        # and nothing about the credentials may reach a response or a log line.
        logger.warning("collection from %s failed: %s", host, type(exc).__name__)
        raise CollectionError(f"collection from {host} failed ({type(exc).__name__})", 502) from None
    finally:
        if session is not None:
            try:
                session.disconnect()
            except Exception:  # a failed disconnect must not mask the result
                pass

    return Collection(
        text="\n\n".join(sections),
        commands=list(commands),
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
    )
