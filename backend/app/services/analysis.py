"""Orchestration: raw configuration in, findings and evidence out.

This is the single place the stages are wired together, so the order of
operations is visible in one screen:

    detect -> parse -> interpret unknowns -> evaluate -> report

The deterministic stages run first and the AI stage runs only over what they
could not resolve. Nothing here decides compliance; that belongs to
app.compliance.engine, which is reached last and reads only the normalised
model.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, computed_field

from app.ai.canonicalize import canonicalize
from app.ai.interpreter import InterpretationOutcome, interpret_unknowns
from app.ai.provider import build_provider
from app.ai.vectorstore import KnowledgeIndex
from app.compliance.engine import ScanResult, evaluate
from app.compliance.rules import RuleCatalog
from app.core.config import Settings, get_settings
from app.core.redaction import redact
from app.parsers.detector import DetectionResult, detect
from app.parsers.engine import parse
from app.parsers.rulepack import MappingRule, RuleOrigin, RulePackLibrary
from app.schema.normalized import NormalizedConfig
from app.schema.parameters import PARAMETER_INDEX, ValueType, coerce_value

logger = logging.getLogger(__name__)


class StageTimings(BaseModel):
    """Per-stage latency, surfaced on the analysis screen and in the report."""

    detection_ms: float = 0.0
    parsing_ms: float = 0.0
    interpretation_ms: float = 0.0
    evaluation_ms: float = 0.0

    @computed_field
    @property
    def total_ms(self) -> float:
        return round(
            self.detection_ms + self.parsing_ms + self.interpretation_ms + self.evaluation_ms, 1
        )


class AnalysisResult(BaseModel):
    """Everything produced for one uploaded configuration."""

    config_id: str
    filename: str
    framework: str
    detection: DetectionResult
    normalized: NormalizedConfig
    scan: ScanResult
    ai: InterpretationOutcome
    timings: StageTimings = Field(default_factory=StageTimings)
    secrets_redacted: int = 0
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def _config_id(filename: str, text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"cfg_{digest}"


# --- turning an approved mapping into a rule --------------------------------

def build_rule_from_mapping(
    command: str,
    parameter: str,
    value: Any,
    approved_by: str,
    rule_id: str | None = None,
) -> MappingRule:
    """Convert an administrator's approved mapping into a reusable rule.

    The important behaviour is that this learns the command's *shape*, not the
    literal string. Teaching `ip ssh version 2` produces a rule keyed on
    `ip ssh version <NUM>` that reads the version out of the captured slot, so
    the system also understands `ip ssh version 1` without being told again.

    A literal value rule is used only when the value cannot be recovered from
    the command text -- `no ip http server` carries no slot to read `false` out
    of, so the value is fixed.
    """
    spec = PARAMETER_INDEX.get(parameter)
    if spec is None:
        raise ValueError(f"'{parameter}' is not a canonical parameter")

    coerced = coerce_value(parameter, value)
    template, slots = canonicalize(command)
    if not template:
        raise ValueError("command is empty after canonicalisation")

    value_rule = f"literal:{str(coerced).lower() if isinstance(coerced, bool) else coerced}"

    # Prefer reading the value from a captured slot so the rule generalises.
    for position, slot in enumerate(slots):
        if spec.value_type is ValueType.INTEGER:
            digits = "".join(ch for ch in slot if ch.isdigit())
            if digits and int(digits) == coerced:
                value_rule = (
                    f"slot:{position}" if slot.isdigit() else f"slot:{position}:digits"
                )
                break
        elif spec.value_type is ValueType.STRING and slot == coerced:
            value_rule = f"slot:{position}"
            break

    generated_id = rule_id or f"learned-{hashlib.sha1(template.encode()).hexdigest()[:10]}"

    return MappingRule(
        id=generated_id,
        parameter=parameter,
        value_rule=value_rule,
        template=template,
        description=f"Learned from an administrator-approved mapping of `{command.strip()}`.",
        origin=RuleOrigin.LEARNED,
        approved_by=approved_by,
        approved_at=datetime.now(timezone.utc).isoformat(),
    )


class AnalysisEngine:
    """Holds the loaded knowledge and runs configurations through it."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.library = RulePackLibrary(self.settings.knowledge_dir)
        self.catalog = RuleCatalog.load(self.settings.rules_path)
        self.index = KnowledgeIndex(self.library, self.settings.embedding_model)
        self.provider = build_provider(self.settings)

    # --- knowledge lifecycle ----------------------------------------------

    def warm_up(self) -> None:
        """Load the embedding model ahead of the first request.

        Cold-loading the ONNX weights takes seconds. Doing it at startup keeps
        that out of the first analysis, which in a live demo is the one anybody
        is timing.
        """
        try:
            self.index.build()
        except Exception as exc:  # never let warm-up failure stop the service
            logger.warning("Knowledge index warm-up failed: %s", exc)

    def reload_knowledge(self) -> None:
        """Re-read rule packs and rebuild the index after a mapping is taught."""
        self.library.reload()
        self.index.build()

    # --- the pipeline ------------------------------------------------------

    def analyze(self, text: str, filename: str, framework: str = "ALL") -> AnalysisResult:
        timings = StageTimings()

        mark = time.perf_counter()
        detection = detect(text, self.library)
        timings.detection_ms = round((time.perf_counter() - mark) * 1000, 1)

        # An unrecognised vendor is not a dead end. The generic pack carries no
        # vendor rules, so every security-relevant line flows to the AI layer
        # and then to the training queue -- which is the path that lets the
        # platform take on a vendor nobody has written a parser for.
        pack_name = detection.vendor if detection.is_known else "generic"
        pack = self.library.get(pack_name)
        if pack is None:
            raise RuntimeError(f"rule pack '{pack_name}' is missing")

        mark = time.perf_counter()
        normalized = parse(text, pack)
        timings.parsing_ms = round((time.perf_counter() - mark) * 1000, 1)

        ai = interpret_unknowns(
            normalized.unknown_commands,
            detection.vendor,
            self.index,
            self.provider,
            self.settings,
        )
        timings.interpretation_ms = ai.duration_ms

        # Model-derived readings join the normalised model, but carry their
        # provenance with them; the compliance engine treats them accordingly.
        normalized.facts.extend(ai.facts)
        normalized.unknown_commands = ai.unknowns
        for fact in ai.facts:
            key = fact.source_type.value
            normalized.stats.facts_by_source[key] = normalized.stats.facts_by_source.get(key, 0) + 1

        mark = time.perf_counter()
        scan = evaluate(normalized, self.catalog, framework)
        timings.evaluation_ms = round((time.perf_counter() - mark) * 1000, 1)

        _, secret_count = redact(text)

        return AnalysisResult(
            config_id=_config_id(filename, text),
            filename=filename,
            framework=framework,
            detection=detection,
            normalized=normalized,
            scan=scan,
            ai=ai,
            timings=timings,
            secrets_redacted=secret_count,
        )

    # --- teaching ----------------------------------------------------------

    def teach(
        self,
        vendor: str,
        command: str,
        parameter: str,
        value: Any,
        approved_by: str = "administrator",
    ) -> MappingRule:
        """Persist an approved mapping and make it active immediately.

        The rule is written into the vendor's pack on disk and the library is
        reloaded, so the next analysis recognises the command deterministically
        -- no retraining, no redeployment, and no model in the loop on the
        second encounter.
        """
        target = vendor if self.library.get(vendor) else "generic"
        rule = build_rule_from_mapping(command, parameter, value, approved_by)
        self.library.add_learned_rule(target, rule)
        # Append rather than rebuild: approval is interactive, and re-encoding
        # the whole corpus made each click take seconds.
        self.index.add(target, rule)
        logger.info("Learned %s -> %s for vendor %s", rule.template, parameter, target)
        return rule

    # --- introspection for the UI -----------------------------------------

    def knowledge_summary(self) -> dict[str, Any]:
        packs = []
        for pack in self.library.all():
            packs.append(
                {
                    "vendor": pack.vendor,
                    "display_name": pack.display_name,
                    "os_family": pack.os_family,
                    "builtin_rules": len(pack.builtin_rules),
                    "learned_rules": len(pack.learned_rules),
                    "defaults": len(pack.defaults),
                }
            )
        return {
            "packs": packs,
            "total_rules": sum(len(p.rules) for p in self.library.all()),
            "total_learned": sum(len(p.learned_rules) for p in self.library.all()),
            "index_size": self.index.size,
            "retrieval_backend": self.index.backend_name,
            "llm_available": self.provider.available,
            "llm_backend": self.provider.name,
            "controls": len(self.catalog.rules),
            "frameworks": [f.model_dump() for f in self.catalog.frameworks],
        }
