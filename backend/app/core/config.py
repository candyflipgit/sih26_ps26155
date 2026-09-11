"""Application settings.

The AI provider is expressed as a base URL plus a model name rather than as a
named vendor integration. Groq, Hugging Face's router, OpenRouter, Together and
a local Ollama or vLLM server all speak the same OpenAI-compatible dialect, so
one client covers every one of them and switching host is an edit to `.env`
rather than a code change.

That is also the offline story: point `LLM_BASE_URL` at `http://localhost:11434/v1`
and the identical pipeline runs against open weights on the operator's own
hardware, with no configuration data leaving their network.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "NetBaseline AI"
    api_prefix: str = "/api/v1"

    # --- storage -----------------------------------------------------------
    data_dir: Path = BACKEND_ROOT / "data"
    upload_dir: Path = BACKEND_ROOT / "data" / "uploads"
    report_dir: Path = BACKEND_ROOT / "data" / "reports"
    database_url: str = f"sqlite:///{(BACKEND_ROOT / 'data' / 'netbaseline.db').as_posix()}"

    # --- language model ----------------------------------------------------
    # Defaults point at Groq's OpenAI-compatible endpoint serving open weights.
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: str = ""
    llm_model: str = "llama-3.3-70b-versatile"
    llm_timeout_seconds: float = 45.0
    llm_max_batch: int = 12
    llm_temperature: float = 0.0

    # --- embeddings --------------------------------------------------------
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    # Retrieval supplies few-shot examples to the model; measurement showed it
    # is not separable enough to decide a mapping alone.
    retrieval_top_k: int = 5

    # --- confidence policy -------------------------------------------------
    # Below this the model's proposal is not even offered as a suggestion. A
    # weak guess presented as a starting point invites rubber-stamping.
    ai_floor_threshold: float = 0.45
    # The bar for auto-acceptance, when auto-acceptance is switched on at all.
    ai_accept_threshold: float = 0.85
    # Off by default, and deliberately so. With this false, a model reading is
    # displayed with its confidence and reasoning but marks the control UNKNOWN
    # rather than PASS or FAIL, until an administrator approves the mapping.
    # An operator who accepts the trade-off can enable it; the safe default is
    # that no model output silently becomes a compliance verdict.
    ai_autoaccept: bool = False

    @property
    def knowledge_dir(self) -> Path:
        return self.data_dir / "knowledge"

    @property
    def rules_path(self) -> Path:
        return self.data_dir / "rules" / "baseline.json"

    @property
    def samples_dir(self) -> Path:
        return self.data_dir / "samples"

    @property
    def llm_configured(self) -> bool:
        """Whether an inference endpoint is actually reachable in this install.

        A local endpoint needs no key, so the presence of a key is not the test;
        a non-default base URL is enough.
        """
        return bool(self.llm_api_key) or "localhost" in self.llm_base_url or "127.0.0.1" in self.llm_base_url

    def ensure_directories(self) -> None:
        for path in (self.upload_dir, self.report_dir):
            path.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
