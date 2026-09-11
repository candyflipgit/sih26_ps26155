"""Retrieval over the mapping knowledge base.

Scope note, because it is easy to overclaim here. Measurement on cross-vendor
CLI text showed dense similarity is not separable enough to pick a mapping on
its own: correct and incorrect neighbours both scored in the 0.74-0.80 band, and
retrieval alone answered barely half of a held-out set. So retrieval is *not* a
decision mechanism in this system. Its job is to put the closest verified
mappings in front of the language model as few-shot precedent, which is a use
that tolerates an imperfect neighbour.

Exact recognition of a previously taught command is handled deterministically by
template matching in the parsing engine, not here.

Backends, in order of preference:
  1. bge-small ONNX embeddings via fastembed -- real semantics, no torch.
  2. character n-gram TF-IDF -- no model download, works fully offline.
Both are wrapped behind the same interface, so an environment that cannot fetch
the ONNX weights degrades in quality rather than breaking.
"""

from __future__ import annotations

import logging
import threading
from typing import Protocol

import numpy as np

from app.parsers.rulepack import MappingRule, RulePackLibrary

logger = logging.getLogger(__name__)


class Embedder(Protocol):
    name: str

    def encode(self, texts: list[str]) -> np.ndarray:
        ...


class OnnxEmbedder:
    """bge-small via fastembed. ~130MB ONNX model, CPU only, no torch."""

    name = "bge-small-en-v1.5 (ONNX)"

    def __init__(self, model_name: str) -> None:
        from fastembed import TextEmbedding

        self._model = TextEmbedding(model_name=model_name)

    def encode(self, texts: list[str]) -> np.ndarray:
        vectors = np.array(list(self._model.embed(texts)), dtype=np.float32)
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.clip(norms, 1e-9, None)


class TfidfEmbedder:
    """Character n-gram TF-IDF. No download, no network, always available."""

    name = "char n-gram TF-IDF (offline fallback)"

    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
        self._fitted = False

    def fit(self, texts: list[str]) -> None:
        if texts:
            self._vec.fit(texts)
            self._fitted = True

    def encode(self, texts: list[str]) -> np.ndarray:
        if not self._fitted:
            self.fit(texts)
        matrix = self._vec.transform(texts).toarray().astype(np.float32)
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        return matrix / np.clip(norms, 1e-9, None)


class KnowledgeIndex:
    """Similarity index over every mapping rule the platform knows.

    Brute-force cosine over a few hundred vectors. A vector database would add
    a service to operate and a dependency to install in exchange for nothing
    measurable at this scale -- exact search over 300 rows is sub-millisecond.
    The interface is narrow enough to swap if the corpus ever grows.
    """

    def __init__(self, library: RulePackLibrary, model_name: str) -> None:
        self.library = library
        self.model_name = model_name
        self._embedder: Embedder | None = None
        self._matrix: np.ndarray | None = None
        self._entries: list[tuple[str, MappingRule]] = []
        self._lock = threading.Lock()

    # --- backend selection -------------------------------------------------

    def _get_embedder(self) -> Embedder:
        if self._embedder is None:
            try:
                self._embedder = OnnxEmbedder(self.model_name)
                logger.info("Retrieval backend: %s", self._embedder.name)
            except Exception as exc:  # model download or onnxruntime unavailable
                logger.warning("ONNX embeddings unavailable (%s); using TF-IDF fallback", exc)
                self._embedder = TfidfEmbedder()
        return self._embedder

    @property
    def backend_name(self) -> str:
        return self._embedder.name if self._embedder else "not yet loaded"

    # --- corpus ------------------------------------------------------------

    @staticmethod
    def _surface(vendor: str, rule: MappingRule) -> str:
        pattern = rule.template or rule.regex or ""
        return f"{vendor} {pattern} {rule.description}".strip()

    def build(self) -> None:
        """Embed every known mapping. Safe to call repeatedly."""
        with self._lock:
            entries: list[tuple[str, MappingRule]] = []
            for pack in self.library.all():
                for rule in pack.rules:
                    entries.append((pack.vendor, rule))

            self._entries = entries
            if not entries:
                self._matrix = None
                return

            texts = [self._surface(v, r) for v, r in entries]
            embedder = self._get_embedder()
            if isinstance(embedder, TfidfEmbedder):
                embedder.fit(texts)
            self._matrix = embedder.encode(texts)

    def add(self, vendor: str, rule: MappingRule) -> None:
        """Append one newly learned rule without re-encoding the whole corpus.

        Approving a mapping is an interactive action, and a full rebuild made it
        take several seconds once the corpus passed a few dozen rules. Encoding
        the single new row and stacking it keeps approval effectively instant,
        which matters because an administrator classifying a queue does this
        repeatedly.
        """
        with self._lock:
            if self._matrix is None:
                # Nothing built yet; a full build is the cheaper path.
                self._entries.append((vendor, rule))
                return

            vector = self._get_embedder().encode([self._surface(vendor, rule)])
            self._matrix = np.vstack([self._matrix, vector])
            self._entries.append((vendor, rule))

    @property
    def size(self) -> int:
        return len(self._entries)

    # --- query -------------------------------------------------------------

    def similar(self, command: str, vendor: str = "", k: int = 5) -> list[tuple[MappingRule, str, float]]:
        """Return the k closest known mappings as (rule, vendor, score)."""
        if self._matrix is None:
            self.build()
        if self._matrix is None or not self._entries:
            return []

        query = self._get_embedder().encode([f"{vendor} {command}".strip()])[0]
        scores = self._matrix @ query
        top = np.argsort(-scores)[: min(k, len(self._entries))]
        return [
            (self._entries[i][1], self._entries[i][0], float(scores[i]))
            for i in top
        ]

    def examples_for_prompt(self, command: str, vendor: str = "", k: int = 5) -> list[str]:
        """Render nearby mappings as few-shot lines for the model."""
        lines: list[str] = []
        for rule, rule_vendor, _score in self.similar(command, vendor, k):
            pattern = rule.template or rule.regex or ""
            lines.append(f"{rule_vendor}: `{pattern}` => {rule.parameter}")
        return lines
