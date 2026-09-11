"""PDF report generation.

The report is the deliverable an auditor keeps, so it is built to be defensible
rather than merely attractive. Every finding carries the configuration line it
was derived from, the rule and rule version that judged it, and the provenance
of the underlying reading. A reader who disagrees with a verdict can trace it
back to the exact text that produced it.

Two details are easy to get wrong and matter here. Evidence lines are redacted
before they are drawn, because a report circulates far more widely than the
configuration it describes. And anything a model contributed is labelled as
such, so no reader mistakes an interpretation for a measurement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.compliance.engine import ScanResult
from app.compliance.remediation import RemediationLibrary
from app.compliance.rules import Severity, Status
from app.core.redaction import redact_line
from app.schema.normalized import NormalizedConfig, SourceType

# --- palette ---------------------------------------------------------------

INK = colors.HexColor("#12181f")
MUTED = colors.HexColor("#5b6672")
HAIRLINE = colors.HexColor("#d8dee5")
PANEL = colors.HexColor("#f4f6f8")
ACCENT = colors.HexColor("#1c4e80")

SEVERITY_COLOR = {
    Severity.CRITICAL: colors.HexColor("#a4161a"),
    Severity.HIGH: colors.HexColor("#d95d0e"),
    Severity.MEDIUM: colors.HexColor("#b08900"),
    Severity.LOW: colors.HexColor("#4a6fa5"),
}

STATUS_COLOR = {
    Status.PASS: colors.HexColor("#2d6a4f"),
    Status.FAIL: colors.HexColor("#a4161a"),
    Status.UNKNOWN: colors.HexColor("#5b6672"),
    Status.NOT_APPLICABLE: colors.HexColor("#8a939d"),
}


def _hex(color: colors.Color) -> str:
    """ReportLab's inline colour markup needs the leading hash that hexval drops."""
    return "#" + color.hexval()[2:]


def _esc(value: object) -> str:
    """Escape text before it is interpolated into ReportLab's markup.

    Paragraph content is parsed as mini-HTML, so any angle bracket in the data
    is read as a tag. Two sources make this unavoidable rather than theoretical:
    the redaction mask is literally `<REDACTED>`, and remediation templates are
    full of placeholders like `<interface>`. Both would otherwise abort the
    render or silently swallow the rest of the line.
    """
    return escape(str(value), {'"': "&quot;", "'": "&#39;"})


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=19, leading=23, textColor=INK, alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=13, textColor=MUTED, spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=12.5, leading=15, textColor=ACCENT, spaceBefore=13, spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=10, leading=13, textColor=INK, spaceBefore=8, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.8, leading=12.2, textColor=INK, spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.6, leading=10.4, textColor=MUTED,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"], fontName="Courier",
            fontSize=7.8, leading=10.6, textColor=INK,
        ),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=10.5, textColor=INK,
        ),
    }


class ScoreBar(Flowable):
    """A compact horizontal bar showing the compliance score."""

    def __init__(self, score: float, width: float, height: float = 9) -> None:
        super().__init__()
        self.score = max(0.0, min(100.0, score))
        self.width = width
        self.height = height

    def draw(self) -> None:
        canvas = self.canv
        canvas.setFillColor(HAIRLINE)
        canvas.roundRect(0, 0, self.width, self.height, 2, stroke=0, fill=1)

        if self.score >= 80:
            tone = colors.HexColor("#2d6a4f")
        elif self.score >= 50:
            tone = colors.HexColor("#b08900")
        else:
            tone = colors.HexColor("#a4161a")

        filled = self.width * self.score / 100.0
        if filled > 0:
            canvas.setFillColor(tone)
            canvas.roundRect(0, 0, max(filled, 3), self.height, 2, stroke=0, fill=1)


class SeverityChart(Flowable):
    """Bar chart of failures by severity, drawn without a charting dependency."""

    def __init__(self, counts: list[tuple[Severity, int]], width: float, height: float = 62) -> None:
        super().__init__()
        self.counts = counts
        self.width = width
        self.height = height

    def draw(self) -> None:
        canvas = self.canv
        peak = max((c for _, c in self.counts), default=0)
        if peak == 0:
            canvas.setFont("Helvetica-Oblique", 8)
            canvas.setFillColor(MUTED)
            canvas.drawString(0, self.height / 2, "No failed controls.")
            return

        slot = self.width / len(self.counts)
        bar_width = min(slot * 0.44, 30)
        floor = 13.0
        usable = self.height - floor - 9

        for position, (severity, count) in enumerate(self.counts):
            centre = slot * position + slot / 2
            bar_height = (count / peak) * usable if count else 0

            canvas.setFillColor(SEVERITY_COLOR[severity])
            if bar_height > 0:
                canvas.rect(centre - bar_width / 2, floor, bar_width, bar_height, stroke=0, fill=1)

            canvas.setFont("Helvetica-Bold", 8.5)
            canvas.drawCentredString(centre, floor + bar_height + 2.5, str(count))

            canvas.setFont("Helvetica", 6.6)
            canvas.setFillColor(MUTED)
            canvas.drawCentredString(centre, floor - 8, severity.value)


class ReportBuilder:
    """Renders one analysis into a single self-contained PDF."""

    MARGIN = 16 * mm

    def __init__(self, remediation: RemediationLibrary) -> None:
        self.remediation = remediation
        self.styles = _styles()

    # --- page furniture ----------------------------------------------------

    def _decorate(self, canvas, doc) -> None:
        canvas.saveState()
        width, height = A4

        canvas.setStrokeColor(HAIRLINE)
        canvas.setLineWidth(0.5)
        canvas.line(self.MARGIN, height - self.MARGIN + 5, width - self.MARGIN, height - self.MARGIN + 5)

        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(ACCENT)
        canvas.drawString(self.MARGIN, height - self.MARGIN + 9, "NETWORK SECURITY COMPLIANCE REPORT")

        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(width - self.MARGIN, height - self.MARGIN + 9, self._header_right)

        canvas.line(self.MARGIN, self.MARGIN - 6, width - self.MARGIN, self.MARGIN - 6)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(
            self.MARGIN, self.MARGIN - 14,
            "Generated by an automated analysis. Verify remediation against your change-control process before applying.",
        )
        canvas.drawRightString(width - self.MARGIN, self.MARGIN - 14, f"Page {doc.page}")
        canvas.restoreState()

    # --- sections ----------------------------------------------------------

    def _kv_table(self, rows: list[tuple[str, str]], width: float) -> Table:
        style = self.styles
        data = [
            [Paragraph(_esc(k), style["small"]), Paragraph(f"<b>{_esc(v)}</b>", style["cell"])]
            for k, v in rows
        ]
        table = Table(data, colWidths=[width * 0.38, width * 0.62], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        return table

    def _summary_block(self, result, width: float) -> list:
        style = self.styles
        summary = result.scan.summary
        device = result.normalized.device
        detection = result.detection

        identity = [
            ("Hostname", device.hostname or "not stated"),
            ("Vendor", detection.display_name),
            ("Model", device.model or "not stated"),
            ("OS / version", f"{device.os_family or '-'} {device.os_version or ''}".strip()),
            ("Serial number", device.serial_number or "not stated"),
        ]
        posture = [
            ("Framework", result.framework),
            ("Controls evaluated", f"{summary.evaluated} of {summary.evaluated + summary.unknown}"),
            ("Passed", str(summary.passed)),
            ("Failed", str(summary.failed)),
            ("Undetermined", str(summary.unknown)),
        ]

        half = (width - 8 * mm) / 2
        columns = Table(
            [[self._kv_table(identity, half), self._kv_table(posture, half)]],
            colWidths=[half + 4 * mm, half + 4 * mm], hAlign="LEFT",
        )
        columns.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))

        score_cells = [[
            Paragraph(f"<font size=25><b>{summary.score:.0f}%</b></font>", style["body"]),
            Paragraph(
                f"<b>Compliance score</b><br/>"
                f"<font size=7.5 color='#5b6672'>{summary.passed} of {summary.evaluated} decidable "
                f"controls passed. Coverage {summary.coverage:.0f}% &mdash; undetermined controls are "
                f"excluded from the score rather than counted as failures.</font>",
                style["cell"],
            ),
        ]]
        score_table = Table(score_cells, colWidths=[26 * mm, width - 26 * mm - 8 * mm], hAlign="LEFT")
        score_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.5, HAIRLINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))

        breakdown = summary.failed_by_severity
        return [
            Paragraph("Executive summary", style["h2"]),
            score_table,
            Spacer(1, 4),
            ScoreBar(summary.score, width),
            Spacer(1, 9),
            columns,
            Spacer(1, 8),
            Paragraph("Failed controls by severity", style["h3"]),
            SeverityChart(
                [
                    (Severity.CRITICAL, breakdown.critical),
                    (Severity.HIGH, breakdown.high),
                    (Severity.MEDIUM, breakdown.medium),
                    (Severity.LOW, breakdown.low),
                ],
                width * 0.6,
            ),
        ]

    def _findings_table(self, scan: ScanResult, width: float) -> Table:
        style = self.styles
        header = ["Control", "Status", "Severity", "Observed", "Evidence"]
        rows = [[Paragraph(f"<b>{h}</b>", style["small"]) for h in header]]

        for finding in scan.findings:
            evidence = finding.evidence[0].text if finding.evidence else "no matching statement"
            rows.append([
                Paragraph(f"<b>{_esc(finding.rule_id)}</b><br/>"
                          f"<font size=7 color='#5b6672'>{_esc(finding.title)}</font>", style["cell"]),
                Paragraph(f"<font color='{_hex(STATUS_COLOR[finding.status])}'>"
                          f"<b>{finding.status.value}</b></font>", style["cell"]),
                Paragraph(f"<font color='{_hex(SEVERITY_COLOR[finding.severity])}'>"
                          f"{finding.severity.value}</font>", style["cell"]),
                Paragraph(_esc(finding.actual), style["cell"]),
                Paragraph(_esc(redact_line(evidence)[:78]), style["mono"]),
            ])

        table = Table(
            rows,
            colWidths=[width * 0.27, width * 0.09, width * 0.10, width * 0.10, width * 0.44],
            repeatRows=1, hAlign="LEFT",
        )
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), PANEL),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, HAIRLINE),
            ("LINEBELOW", (0, 1), (-1, -2), 0.25, HAIRLINE),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    def _detail(self, finding, vendor: str, width: float) -> list:
        style = self.styles
        tone = _hex(SEVERITY_COLOR[finding.severity])

        block: list = [
            Paragraph(
                f"<font color='{tone}'><b>{finding.severity.value}</b></font> &nbsp; "
                f"<b>{_esc(finding.rule_id)}</b> &mdash; {_esc(finding.title)}",
                style["h3"],
            ),
            Paragraph(_esc(finding.description), style["body"]),
        ]

        if finding.impact:
            block.append(Paragraph(f"<b>Why this matters.</b> {_esc(finding.impact)}", style["body"]))

        block.append(Paragraph(
            f"<b>Expected</b> {_esc(finding.parameter)} "
            f"{_esc(finding.operator.value.replace('_', ' '))} "
            f"<b>{_esc(finding.expected)}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Observed</b> {_esc(finding.actual)}",
            style["body"],
        ))

        if finding.evidence:
            block.append(Paragraph("Evidence from the configuration:", style["small"]))
            for item in finding.evidence[:4]:
                block.append(Paragraph(
                    f"line {item.line_number}: {_esc(redact_line(item.text)[:96])}", style["mono"]
                ))
        elif finding.normalisation_rationale:
            block.append(Paragraph(
                f"<i>{_esc(finding.normalisation_rationale)}</i>", style["small"]
            ))

        if finding.source_type and finding.source_type.is_ai_assisted:
            block.append(Paragraph(
                f"<b>AI-assisted reading.</b> Interpreted by the semantic layer at "
                f"{finding.confidence:.0%} confidence"
                + (f": {_esc(finding.normalisation_rationale)}"
                   if finding.normalisation_rationale else "")
                + (". Pending administrator confirmation, so this control is reported as "
                   "undetermined rather than as a pass or a failure."
                   if finding.requires_review else "."),
                style["small"],
            ))

        references = [f"{_esc(k)}: {_esc(', '.join(v))}" for k, v in finding.frameworks.items()]
        if references:
            block.append(Paragraph(
                f"<b>Framework references.</b> {' &nbsp;|&nbsp; '.join(references)}", style["small"]
            ))

        if finding.status is Status.FAIL:
            plan = self.remediation.plan_for(finding.remediation_id, vendor)
            if plan is not None:
                block.append(Spacer(1, 3))
                if plan.vendor_specific and plan.commands:
                    block.append(Paragraph(
                        f"Remediation &mdash; {_esc(plan.title)}", style["small"]
                    ))
                    # Escape first, then convert leading indentation to
                    # non-breaking spaces so the command block keeps its shape.
                    body = "<br/>".join(
                        _esc(command).replace(" ", "&nbsp;") for command in plan.commands
                    )
                    command_table = Table([[Paragraph(body, style["mono"])]],
                                          colWidths=[width], hAlign="LEFT")
                    command_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                        ("BOX", (0, 0), (-1, -1), 0.4, HAIRLINE),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]))
                    block.append(command_table)
                    if plan.note:
                        block.append(Paragraph(f"Note. {_esc(plan.note)}", style["small"]))
                else:
                    block.append(Paragraph(
                        f"<b>Remediation guidance.</b> {_esc(plan.guidance)} "
                        f"<i>No verified command sequence is published for this platform, so "
                        f"descriptive guidance is given rather than commands to paste.</i>",
                        style["small"],
                    ))

        block.append(Spacer(1, 7))
        return block

    def _provenance(self, result, width: float) -> list:
        style = self.styles
        normalized: NormalizedConfig = result.normalized
        counts = normalized.stats.facts_by_source

        rows = [
            ("Deterministic parser",
             counts.get(SourceType.DETERMINISTIC_PARSER.value, 0),
             "Matched a vendor rule shipped with the platform."),
            ("Administrator knowledge base",
             counts.get(SourceType.KNOWLEDGE_BASE.value, 0),
             "Matched a mapping an administrator previously approved."),
            ("Semantic model",
             counts.get(SourceType.LLM.value, 0),
             "Interpreted by the AI layer; marked for review and excluded from pass/fail."),
        ]

        data = [[Paragraph(f"<b>{h}</b>", style["small"]) for h in ("Source", "Readings", "Meaning")]]
        for label, count, meaning in rows:
            data.append([
                Paragraph(label, style["cell"]),
                Paragraph(str(count), style["cell"]),
                Paragraph(meaning, style["small"]),
            ])

        table = Table(data, colWidths=[width * 0.26, width * 0.11, width * 0.63], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), PANEL),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, HAIRLINE),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))

        return [
            Paragraph("Provenance and assurance", style["h2"]),
            Paragraph(
                "Every value judged in this report was produced by one of the sources below. "
                "Compliance verdicts are computed by deterministic comparison against the rule "
                "catalogue; the AI layer interprets vendor syntax but never decides whether a "
                "configuration is compliant.",
                style["body"],
            ),
            table,
            Spacer(1, 6),
            Paragraph(
                f"{result.secrets_redacted} credential value(s) were detected in the source "
                f"configuration and masked before this report was written. "
                f"Analysis completed in {result.timings.total_ms:.0f} ms "
                f"(detection {result.timings.detection_ms:.0f} ms, parsing "
                f"{result.timings.parsing_ms:.0f} ms, interpretation "
                f"{result.timings.interpretation_ms:.0f} ms, evaluation "
                f"{result.timings.evaluation_ms:.0f} ms).",
                style["small"],
            ),
        ]

    # --- entry point -------------------------------------------------------

    def build(self, result, destination: Path) -> Path:
        style = self.styles
        width = A4[0] - 2 * self.MARGIN
        device = result.normalized.device
        report_id = f"RPT-{datetime.now(timezone.utc):%Y%m%d}-{result.config_id[4:12].upper()}"
        self._header_right = f"{device.display_name} | {report_id}"

        framework_label = (
            "all supported frameworks" if result.framework.upper() == "ALL" else result.framework
        )

        destination.parent.mkdir(parents=True, exist_ok=True)
        doc = BaseDocTemplate(
            str(destination), pagesize=A4,
            leftMargin=self.MARGIN, rightMargin=self.MARGIN,
            topMargin=self.MARGIN + 4, bottomMargin=self.MARGIN + 4,
            title=f"Compliance report {report_id}", author="NetBaseline AI",
        )
        frame = Frame(
            self.MARGIN, self.MARGIN + 4, width,
            A4[1] - 2 * self.MARGIN - 8, id="body",
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        )
        doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=self._decorate)])

        story: list = [
            Paragraph(_esc(device.display_name), style["title"]),
            Paragraph(
                f"{_esc(result.detection.display_name)} &nbsp;&middot;&nbsp; "
                f"assessed against {_esc(framework_label)} &nbsp;&middot;&nbsp; "
                f"report {report_id} &nbsp;&middot;&nbsp; "
                f"{result.analyzed_at:%d %B %Y, %H:%M UTC}",
                style["subtitle"],
            ),
        ]

        story += self._summary_block(result, width)

        story.append(Paragraph("Control results", style["h2"]))
        story.append(self._findings_table(result.scan, width))

        failures = result.scan.failures
        if failures:
            story.append(PageBreak())
            story.append(Paragraph("Detailed findings and remediation", style["h2"]))
            story.append(Paragraph(
                "Failed controls, most severe first. Commands are drawn from a curated "
                "per-vendor template library, never generated by a language model.",
                style["small"],
            ))
            story.append(Spacer(1, 5))
            for finding in failures:
                story.append(KeepTogether(self._detail(finding, result.detection.vendor, width)))

        undetermined = [f for f in result.scan.findings if f.status is Status.UNKNOWN]
        if undetermined:
            story.append(Paragraph("Undetermined controls", style["h2"]))
            story.append(Paragraph(
                "The configuration supplied no statement these controls could be judged on, or the "
                "only available reading is awaiting administrator confirmation. They are reported "
                "as undetermined rather than as failures, because reporting an unparsed setting as "
                "a violation would manufacture a false positive.",
                style["body"],
            ))
            for finding in undetermined:
                story.append(Paragraph(
                    f"<b>{_esc(finding.rule_id)}</b> &mdash; {_esc(finding.title)}. "
                    f"{_esc(finding.normalisation_rationale or '')}",
                    style["small"],
                ))
            story.append(Spacer(1, 6))

        queue = result.normalized.unknown_commands
        if queue:
            story.append(Paragraph("Commands awaiting classification", style["h2"]))
            story.append(Paragraph(
                f"{len(queue)} security-relevant statement(s) in this configuration are not yet "
                f"mapped to the security baseline. Each can be classified once in the training "
                f"interface, after which the platform recognises it automatically on every "
                f"subsequent device.",
                style["body"],
            ))
            for unknown in queue[:14]:
                suggestion = ""
                if unknown.suggested_parameter:
                    suggestion = (
                        f"<br/><font color='#5b6672'>proposed: "
                        f"{_esc(unknown.suggested_parameter)} = "
                        f"{_esc(unknown.suggested_value)} at "
                        f"{unknown.suggested_confidence:.0%} confidence, "
                        f"pending approval</font>"
                    )
                story.append(Paragraph(
                    f"line {unknown.line_number}: "
                    f"{_esc(redact_line(unknown.raw)[:92])}{suggestion}",
                    style["mono"],
                ))
            if len(queue) > 14:
                story.append(Paragraph(f"... and {len(queue) - 14} more.", style["small"]))
            story.append(Spacer(1, 6))

        story += self._provenance(result, width)

        doc.build(story)
        return destination
