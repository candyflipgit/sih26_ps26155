"""Remediation guidance.

Remediation commands come from a curated, per-vendor template library, never
from a language model. A hallucinated CLI command in a security report is worse
than no command at all: an administrator may paste it into a production device,
and a plausible-looking but wrong command can lock the operator out of the box
or open a hole neither party intended.

Where no verified template exists for a vendor, the system says so and gives
descriptive guidance instead. Admitting the gap is the correct behaviour.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, Field


class RemediationVariant(BaseModel):
    """Commands that apply only within an OS release range.

    Syntax genuinely drifts between releases: Cisco's scrypt secrets need IOS
    15.3(3)M or later, and per-algorithm SSH cipher control needs 15.5(1)S.
    Handing an administrator a command their release rejects is almost as bad
    as handing them a wrong one.
    """

    min_version: str | None = None  # inclusive
    max_version: str | None = None  # exclusive
    label: str = ""
    commands: list[str] = Field(default_factory=list)
    note: str = ""


class VendorRemediation(BaseModel):
    commands: list[str] = Field(default_factory=list)
    note: str = ""
    variants: list[RemediationVariant] = Field(default_factory=list)


_VERSION_PARTS = re.compile(r"\d+")


def version_key(version: str | None) -> tuple[int, ...] | None:
    """Reduce a vendor version string to comparable integers.

    "17.09.04a" -> (17, 9, 4), "15.2(4)M" -> (15, 2, 4),
    "21.4R3-S5.4" -> (21, 4, 3), "v7.4.4" -> (7, 4, 4).
    """
    if not version:
        return None
    parts = [int(p) for p in _VERSION_PARTS.findall(version)[:3]]
    return tuple(parts) if parts else None


def _in_range(key: tuple[int, ...], variant: RemediationVariant) -> bool:
    def pad(t: tuple[int, ...]) -> tuple[int, ...]:
        return t + (0,) * (3 - len(t))

    low = version_key(variant.min_version)
    high = version_key(variant.max_version)
    if low is not None and pad(key) < pad(low):
        return False
    if high is not None and pad(key) >= pad(high):
        return False
    return True


class RemediationTemplate(BaseModel):
    id: str
    title: str
    summary: str
    vendors: dict[str, VendorRemediation] = Field(default_factory=dict)
    # Used when the device's vendor has no verified template.
    generic: str = ""


class RemediationPlan(BaseModel):
    """What the report and UI show for one failing finding."""

    remediation_id: str
    title: str
    summary: str
    vendor: str
    commands: list[str] = Field(default_factory=list)
    note: str = ""
    guidance: str = ""
    # False when no verified template exists for this vendor, so the UI can say
    # plainly that the text is guidance rather than a command to paste.
    vendor_specific: bool = False
    # The release the commands were chosen for, and why -- so an
    # administrator on an older train is told the syntax may differ.
    os_version: str | None = None
    version_basis: str = ""

    warning: str = (
        "Review against your change-control process before applying. Commands are "
        "written for the detected platform and may need adjustment for your "
        "interface names, ACL names and OS version."
    )


class RemediationLibrary:
    def __init__(self, path: Path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.version: str = data.get("version", "1.0")
        self.templates: dict[str, RemediationTemplate] = {
            key: RemediationTemplate(id=key, **value)
            for key, value in data.get("templates", {}).items()
        }

    def plan_for(
        self,
        remediation_id: str | None,
        vendor: str,
        os_version: str | None = None,
    ) -> RemediationPlan | None:
        """Build the remediation for a finding on a specific platform and release.

        Where a template carries release variants, the one matching the device's
        detected OS version is chosen, and the plan says which release range it
        targets. If the version was not detected, the current-release commands
        are shown and the plan says so plainly rather than implying a match.
        """
        if not remediation_id:
            return None
        template = self.templates.get(remediation_id)
        if template is None:
            return None

        specific = template.vendors.get(vendor)
        if specific is not None:
            commands, note, basis = specific.commands, specific.note, ""

            if specific.variants:
                key = version_key(os_version)
                chosen = (
                    next((v for v in specific.variants if _in_range(key, v)), None)
                    if key is not None
                    else None
                )
                if chosen is not None:
                    commands = chosen.commands or commands
                    note = chosen.note or note
                    basis = f"Commands selected for {os_version} ({chosen.label})."
                elif key is None:
                    basis = (
                        "OS version was not detected, so commands for current releases are "
                        "shown. Confirm the syntax on the device before applying."
                    )
                else:
                    basis = (
                        f"No release-specific variant matched {os_version}; commands for "
                        "current releases are shown."
                    )

            return RemediationPlan(
                remediation_id=template.id,
                title=template.title,
                summary=template.summary,
                vendor=vendor,
                commands=commands,
                note=note,
                vendor_specific=True,
                os_version=os_version,
                version_basis=basis,
            )

        return RemediationPlan(
            remediation_id=template.id,
            title=template.title,
            summary=template.summary,
            vendor=vendor or "unknown",
            guidance=template.generic
            or "No verified command sequence is available for this platform yet.",
            vendor_specific=False,
            os_version=os_version,
        )

    @property
    def coverage(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for template in self.templates.values():
            for vendor in template.vendors:
                counts[vendor] = counts.get(vendor, 0) + 1
        return counts
