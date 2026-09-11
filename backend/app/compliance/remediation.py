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
from pathlib import Path

from pydantic import BaseModel, Field


class VendorRemediation(BaseModel):
    commands: list[str] = Field(default_factory=list)
    note: str = ""


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

    def plan_for(self, remediation_id: str | None, vendor: str) -> RemediationPlan | None:
        """Build the remediation shown for a finding on a specific platform."""
        if not remediation_id:
            return None
        template = self.templates.get(remediation_id)
        if template is None:
            return None

        specific = template.vendors.get(vendor)
        if specific is not None:
            return RemediationPlan(
                remediation_id=template.id,
                title=template.title,
                summary=template.summary,
                vendor=vendor,
                commands=specific.commands,
                note=specific.note,
                vendor_specific=True,
            )

        return RemediationPlan(
            remediation_id=template.id,
            title=template.title,
            summary=template.summary,
            vendor=vendor or "unknown",
            guidance=template.generic
            or "No verified command sequence is available for this platform yet.",
            vendor_specific=False,
        )

    @property
    def coverage(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for template in self.templates.values():
            for vendor in template.vendors:
                counts[vendor] = counts.get(vendor, 0) + 1
        return counts
