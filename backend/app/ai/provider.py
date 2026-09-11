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
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, Field

from app.ai.prompts import build_system_prompt, build_user_prompt
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


class LLMProvider(Protocol):
    name: str
    available: bool

    def interpret(
        self, vendor: str, commands: list[str], examples: list[str]
    ) -> list[AIProposal]:
        ...


class NullProvider:
    """No inference endpoint. Everything unrecognised goes to a human."""

    name = "none"
    available = False

    def interpret(
        self, vendor: str, commands: list[str], examples: list[str]
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

    def interpret(
        self, vendor: str, commands: list[str], examples: list[str]
    ) -> list[AIProposal]:
        """Interpret a batch of commands in a single request.

        Batching matters for a live demo: a configuration with fifteen
        unrecognised lines resolves in one round trip rather than fifteen. Each
        command is numbered and the model must echo the index back, so a
        response cannot silently shift results onto the wrong command.
        """
        if not commands:
            return []
        if not self.available:
            return []

        payload = {
            "model": self.settings.llm_model,
            "temperature": self.settings.llm_temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": build_system_prompt()},
                {"role": "user", "content": build_user_prompt(vendor, commands, examples)},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.settings.llm_api_key:
            headers["Authorization"] = f"Bearer {self.settings.llm_api_key}"

        try:
            response = httpx.post(
                f"{self.settings.llm_base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.settings.llm_timeout_seconds,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            # An inference failure must never fail the scan. The commands stay
            # unknown and surface for human classification instead.
            logger.warning("LLM request failed, falling back to human review: %s", exc)
            return []

        return self._validate(content, commands)

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
