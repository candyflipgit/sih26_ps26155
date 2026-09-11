"""The semantic interpretation pipeline for unrecognised commands.

Tiering, in the order a command is offered to each mechanism:

  Tier 1  Deterministic template match against the vendor rule pack. Instant,
          exact, no model involved. Handled upstream in the parsing engine, and
          this is the tier a taught command lands in on every later run.
  Tier 2  Retrieval of the nearest verified mappings -- used as precedent for
          the model, never as an answer in itself.
  Tier 3  The language model, constrained to the closed parameter vocabulary and
          validated on the way out.
  Tier 4  A human. Anything the model declines, scores poorly, or fails
          validation on becomes a Teach-AI item.

The policy that matters: a model proposal does not, by default, get to influence
a compliance verdict. It is recorded, shown with its confidence and reasoning,
and marked for review -- which makes the control read UNKNOWN rather than
PASS or FAIL. Only after an administrator approves it does the mapping become a
rule, and only then does it carry weight in a result. That is the difference
between a tool that uses AI to save an expert time and one that lets a model
quietly decide whether a firewall is compliant.
"""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, Field, computed_field

from app.ai.provider import AIProposal, LLMProvider
from app.ai.vectorstore import KnowledgeIndex
from app.core.config import Settings
from app.core.redaction import redact_line
from app.schema.normalized import Evidence, NormalizedFact, SourceType, UnknownCommand

logger = logging.getLogger(__name__)


class InterpretationOutcome(BaseModel):
    """What the AI layer produced for one configuration."""

    facts: list[NormalizedFact] = Field(default_factory=list)
    unknowns: list[UnknownCommand] = Field(default_factory=list)
    llm_available: bool = False
    llm_calls: int = 0
    commands_considered: int = 0
    proposals_returned: int = 0
    proposals_accepted: int = 0
    secrets_redacted: int = 0
    duration_ms: float = 0.0
    backend: str = ""

    @computed_field
    @property
    def acceptance_rate(self) -> float:
        if self.commands_considered == 0:
            return 0.0
        return round(100.0 * self.proposals_accepted / self.commands_considered, 1)


def interpret_unknowns(
    unknowns: list[UnknownCommand],
    vendor: str,
    index: KnowledgeIndex,
    provider: LLMProvider,
    settings: Settings,
) -> InterpretationOutcome:
    """Attempt to interpret the commands the deterministic parser could not."""
    started = time.perf_counter()
    outcome = InterpretationOutcome(
        llm_available=provider.available,
        commands_considered=len(unknowns),
        backend=provider.name,
    )

    if not unknowns:
        outcome.duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return outcome

    if not provider.available:
        # No endpoint. Every command stays for a human, which is a degraded
        # mode rather than a failure: the rest of the platform is unaffected.
        outcome.unknowns = list(unknowns)
        outcome.duration_ms = round((time.perf_counter() - started) * 1000, 1)
        return outcome

    # Credentials are stripped before anything leaves the process. The model
    # needs the shape of a command, never the secret inside it.
    redacted: list[str] = []
    for unknown in unknowns:
        clean = redact_line(unknown.raw)
        if clean != unknown.raw:
            outcome.secrets_redacted += 1
        redacted.append(clean)

    by_index: dict[int, AIProposal] = {}
    batch_size = max(1, settings.llm_max_batch)

    contexts = [u.context for u in unknowns]

    for start in range(0, len(redacted), batch_size):
        chunk = redacted[start : start + batch_size]
        chunk_contexts = contexts[start : start + batch_size]

        # Retrieval precedent is gathered per batch from the first command, which
        # keeps the prompt small; the vocabulary in the system prompt is what
        # actually constrains the model.
        examples = index.examples_for_prompt(chunk[0], vendor, settings.retrieval_top_k)

        proposals = provider.interpret(vendor, chunk, examples, chunk_contexts)
        outcome.llm_calls += 1
        outcome.proposals_returned += len(proposals)

        for proposal in proposals:
            absolute = start + proposal.index
            if 0 <= absolute < len(unknowns):
                by_index[absolute] = proposal

    for position, unknown in enumerate(unknowns):
        proposal = by_index.get(position)

        if proposal is None or proposal.confidence < settings.ai_floor_threshold:
            # Either the model declined, or it is too unsure to be worth showing
            # as a suggestion. Presenting a weak guess as a starting point makes
            # a reviewer more likely to rubber-stamp it, not less.
            outcome.unknowns.append(unknown)
            continue

        enriched = unknown.model_copy(
            update={
                "suggested_parameter": proposal.parameter,
                "suggested_value": proposal.value,
                "suggested_confidence": proposal.confidence,
                "suggested_rationale": proposal.reasoning,
            }
        )
        outcome.unknowns.append(enriched)
        outcome.proposals_accepted += 1

        # Record the reading so the normalised view shows what the model
        # understood. `requires_review` keeps it out of any PASS/FAIL verdict
        # until an administrator confirms it.
        outcome.facts.append(
            NormalizedFact(
                parameter=proposal.parameter,
                value=proposal.value,
                confidence=proposal.confidence,
                source_type=SourceType.LLM,
                evidence=[Evidence(line_number=unknown.line_number, text=unknown.raw)],
                rationale=proposal.reasoning,
                requires_review=not (
                    settings.ai_autoaccept and proposal.confidence >= settings.ai_accept_threshold
                ),
            )
        )

    outcome.duration_ms = round((time.perf_counter() - started) * 1000, 1)
    logger.info(
        "AI layer: %d commands, %d calls, %d accepted in %.0fms",
        outcome.commands_considered, outcome.llm_calls, outcome.proposals_accepted,
        outcome.duration_ms,
    )
    return outcome
