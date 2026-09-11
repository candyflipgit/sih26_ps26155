"""Language model providers.

There is exactly one real client, speaking the OpenAI-compatible dialect that
Groq, Hugging Face's router, OpenRouter, Together, Ollama and vLLM all
implement. Choosing a host is configuration, not code.

`NullProvider` is not a stub for tests -- it is the production fallback. When no
endpoint is configured, or the endpoint is down, the platform keeps working:
deterministic parsing, the knowledge base, compliance evaluation and reporting
are all unaffected, and unrecognised commands simply queue for a human. An
inference outage degrades the system; it does not stop it.
"""

from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field

from app.ai.prompts import build_system_prompt, build_user_prompt, new_fence
from app.core.config import Settings
from app.schema.parameters import PARAMETER_INDEX, coerce_value

logger = logging.getLogger(__name__)


class AIProposal(BaseModel):
    """A validated interpretation of one configuration command."""

    index: int
    parameter: str
    value: Any
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""
    # "2/3" when self-consistency is on: how many samples agreed. None for
    # a single-sample run, where no agreement signal exists.
    agreement: str | None = None


class LLMProvider(Protocol):
    name: str
    available: bool

    def interpret(
        self,
        vendor: str,
        commands: list[str],
        examples: list[str],
        contexts: list[str] | None = None,
    ) -> list[AIProposal]:
        ...


class NullProvider:
    """No inference endpoint. Everything unrecognised goes to a human."""

    name = "none"
    available = False

    def interpret(
        self,
        vendor: str,
        commands: list[str],
        examples: list[str],
        contexts: list[str] | None = None,
    ) -> list[AIProposal]:
        return []


_JSON_BLOCK = re.compile(r"\{.*\}", re.S)


def _extract_json(content: str) -> dict[str, Any] | None:
    """Recover a JSON object from a model response.

    Even with a JSON response format requested, some hosts wrap the payload in a
    markdown fence or add a sentence of preamble. Failing the whole batch over
    that would be needless, so try the strict parse first and fall back to the
    outermost brace-delimited span.
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK.search(content)
    if match is None:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


class OpenAICompatProvider:
    """Client for any OpenAI-compatible chat completions endpoint."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.name = f"{settings.llm_model} @ {httpx.URL(settings.llm_base_url).host}"
        self.available = settings.llm_configured

    def _one_pass(
        self,
        vendor: str,
        commands: list[str],
        examples: list[str],
        contexts: list[str] | None,
        temperature: float,
    ) -> list[AIProposal] | None:
        """A single sampled interpretation of the batch.

        Returns None when the request itself failed, and a list when the
        model answered -- possibly with nothing to propose. Self-consistency
        depends on that distinction: a sample that never reached the
        endpoint has no opinion, whereas a sample that answered "no mapping"
        is casting a real vote against one.
        """
        marker, nonce = new_fence()

        payload = {
            "model": self.settings.llm_model,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": build_system_prompt(marker)},
                {
                    "role": "user",
                    "content": build_user_prompt(
                        vendor, commands, examples, contexts, marker, nonce
                    ),
                },
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.settings.llm_api_key:
            headers["Authorization"] = f"Bearer {self.settings.llm_api_key}"

        url = f"{self.settings.llm_base_url.rstrip('/')}/chat/completions"
        content: str | None = None

        # Rate limits are a fact of life on free inference tiers, and scanning
        # several devices in a row is exactly what a demo does. A 429 is a
        # "wait" not a "no", so honour Retry-After and back off rather than
        # discarding work the endpoint was willing to do a second later.
        for attempt in range(self.settings.llm_max_retries + 1):
            try:
                response = httpx.post(
                    url, json=payload, headers=headers,
                    timeout=self.settings.llm_timeout_seconds,
                )

                if response.status_code == 429 and attempt < self.settings.llm_max_retries:
                    header = response.headers.get("retry-after", "")
                    try:
                        wait = float(header)
                    except ValueError:
                        wait = 0.0
                    wait = min(max(wait, 2.0 ** attempt), self.settings.llm_max_backoff_seconds)
                    logger.info("rate limited, retrying in %.1fs (attempt %d)", wait, attempt + 1)
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                break

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code >= 500 and attempt < self.settings.llm_max_retries:
                    time.sleep(min(2.0 ** attempt, self.settings.llm_max_backoff_seconds))
                    continue
                logger.warning("LLM request failed, falling back to human review: %s", exc)
                return None
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                # An inference failure must never fail the scan. The commands
                # stay unknown and surface for human classification instead.
                logger.warning("LLM request failed, falling back to human review: %s", exc)
                return None

        if content is None:
            logger.warning("LLM still rate limited after retries; deferring to human review")
            return None

        return self._validate(content, commands)

    def interpret(
        self,
        vendor: str,
        commands: list[str],
        examples: list[str],
        contexts: list[str] | None = None,
    ) -> list[AIProposal]:
        """Interpret a batch of commands, optionally via self-consistency.

        Batching matters for a live demo: a configuration with fifteen
        unrecognised lines resolves in one round trip rather than fifteen. Each
        command is numbered and the model must echo the index back, so a
        response cannot silently shift results onto the wrong command.

        When `llm_samples` is greater than one the batch is sampled several
        times concurrently and the results are reconciled by agreement. This
        exists because a model's *stated* confidence is not a calibrated
        probability -- the literature finds verbalized confidence systematically
        overconfident above 0.5, and in our own runs this model returned 1.00 on
        every single proposal, which makes a confidence threshold meaningless.
        How often independent samples land on the same mapping is a signal the
        model cannot simply assert.
        """
        if not commands or not self.available:
            return []

        samples = max(1, self.settings.llm_samples)
        if samples == 1:
            return self._one_pass(
                vendor, commands, examples, contexts, self.settings.llm_temperature
            ) or []

        # Concurrent, so wall-clock cost stays close to a single call.
        # Temperature must be non-zero or every sample is identical and
        # agreement measures nothing.
        temperature = max(self.settings.llm_temperature, 0.3)
        runs: list[list[AIProposal]] = []
        with ThreadPoolExecutor(max_workers=samples) as pool:
            futures = [
                pool.submit(self._one_pass, vendor, commands, examples, contexts, temperature)
                for _ in range(samples)
            ]
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:  # one bad sample must not sink the batch
                    logger.warning("sample raised: %s", exc)
                    continue
                if result is not None:
                    runs.append(result)

        if not runs:
            return []
        if len(runs) < 2:
            # One surviving sample cannot measure agreement with itself.
            # Reporting 1/1 as full agreement would manufacture confidence out
            # of a rate limit, so fall back to the single run untouched.
            logger.warning("only one sample survived; reporting it without an agreement score")
            return runs[0]
        if len(runs) < samples:
            # A partial vote is still a vote, but say so: with a free-tier rate
            # limit, concurrent sampling is the first thing to be throttled.
            logger.warning(
                "self-consistency degraded: %d of %d samples returned", len(runs), samples
            )
        return self._reconcile(runs, len(commands))

    @staticmethod
    def _reconcile(runs: list[list[AIProposal]], count: int) -> list[AIProposal]:
        """Merge several samples into one answer set, scored by agreement.

        For each command the most frequently proposed (parameter, value) pair
        wins, and confidence becomes the share of samples that produced it. A
        command only one sample in three interpreted scores 0.33 and drops below
        the review floor, which is the behaviour we want: disagreement among
        samples is precisely the case a human should look at.

        Declining counts as a vote. If two of three samples decline, the
        agreement is that there is no mapping, and nothing is proposed.
        """
        if not runs:
            return []

        total = len(runs)
        merged: list[AIProposal] = []

        for index in range(count):
            votes: dict[tuple[str, str], list[AIProposal]] = {}
            abstentions = 0

            for run in runs:
                proposal = next((p for p in run if p.index == index), None)
                if proposal is None:
                    abstentions += 1
                    continue
                key = (proposal.parameter, repr(proposal.value))
                votes.setdefault(key, []).append(proposal)

            if not votes:
                continue

            winner_key, winning = max(votes.items(), key=lambda kv: len(kv[1]))
            if len(winning) <= abstentions:
                # More samples declined than agreed on any single mapping.
                continue

            agreement = len(winning) / total
            exemplar = winning[0]
            # Keep the model's own estimate only as a tie-break within the
            # agreement level; agreement itself dominates.
            stated = sum(p.confidence for p in winning) / len(winning)
            merged.append(
                exemplar.model_copy(
                    update={
                        "confidence": round(agreement * 0.8 + stated * 0.2, 3),
                        "reasoning": exemplar.reasoning,
                        "agreement": f"{len(winning)}/{total}",
                    }
                )
            )

        return merged

    def _validate(self, content: str, commands: list[str]) -> list[AIProposal]:
        """Turn a raw model response into proposals we are willing to act on.

        This is the choke point that keeps a hallucination out of the security
        pipeline. A result is discarded unless it names a parameter that exists
        in the registry, carries a value of the declared type, and points at a
        command that was actually sent.
        """
        parsed = _extract_json(content)
        if not parsed:
            logger.warning("LLM response was not valid JSON; discarding batch")
            return []

        raw_results = parsed.get("results")
        if not isinstance(raw_results, list):
            return []

        proposals: list[AIProposal] = []
        seen: set[int] = set()

        for item in raw_results:
            if not isinstance(item, dict):
                continue

            index = item.get("index")
            if not isinstance(index, int) or not 0 <= index < len(commands) or index in seen:
                continue

            parameter = item.get("parameter")
            if not isinstance(parameter, str) or parameter not in PARAMETER_INDEX:
                # Either the model declined, or it invented a parameter. Both
                # mean the command stays unknown.
                continue

            try:
                confidence = float(item.get("confidence", 0.0))
            except (TypeError, ValueError):
                continue
            confidence = max(0.0, min(1.0, confidence))

            try:
                value = coerce_value(parameter, item.get("value"))
            except (ValueError, TypeError):
                logger.debug("discarding %s: value %r is not valid for the parameter",
                             parameter, item.get("value"))
                continue

            reasoning = item.get("reasoning")
            proposals.append(
                AIProposal(
                    index=index,
                    parameter=parameter,
                    value=value,
                    confidence=confidence,
                    reasoning=str(reasoning)[:300] if reasoning else "",
                )
            )
            seen.add(index)

        return proposals


def build_provider(settings: Settings) -> LLMProvider:
    if not settings.llm_configured:
        logger.info("No inference endpoint configured; running in retrieval-only mode")
        return NullProvider()
    return OpenAICompatProvider(settings)
