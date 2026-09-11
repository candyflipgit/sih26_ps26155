"""Vendor and OS detection.

Deliberately deterministic. Identifying that a file full of `set system
services` lines is Junos does not need a language model, and using one here
would add latency and a failure mode in exchange for nothing. Each rule pack
declares weighted signature tokens; the detector scores the configuration
against every pack and reports a normalised confidence.

When nothing scores above the threshold the answer is `unknown`, which is not a
dead end: the file still flows into the AI layer, and every security-relevant
line lands in the Teach-AI queue. That path is what lets the platform accept a
vendor it has never seen.
"""

from __future__ import annotations

from pydantic import BaseModel

from app.parsers.rulepack import RulePack, RulePackLibrary

# Below this normalised score the evidence is too thin to name a vendor.
CONFIDENCE_THRESHOLD = 0.25


class DetectionResult(BaseModel):
    vendor: str
    display_name: str
    confidence: float
    # Every candidate's score, so the UI can show why a call was made.
    scores: dict[str, float] = {}
    matched_signatures: list[str] = []

    @property
    def is_known(self) -> bool:
        return self.vendor != "unknown"


def _score(config_lower: str, pack: RulePack) -> tuple[float, list[str]]:
    total = sum(pack.signatures.values()) or 1.0
    hit = 0.0
    matched: list[str] = []
    for token, weight in pack.signatures.items():
        if token.lower() in config_lower:
            hit += weight
            matched.append(token)
    return hit / total, matched


def detect(config: str, library: RulePackLibrary) -> DetectionResult:
    """Identify which vendor rule pack should parse this configuration."""
    lowered = config.lower()

    scores: dict[str, float] = {}
    matches: dict[str, list[str]] = {}
    for pack in library.all():
        score, matched = _score(lowered, pack)
        scores[pack.vendor] = round(score, 3)
        matches[pack.vendor] = matched

    if not scores:
        return DetectionResult(vendor="unknown", display_name="Unrecognised vendor", confidence=0.0)

    best = max(scores, key=lambda v: scores[v])
    best_score = scores[best]

    if best_score < CONFIDENCE_THRESHOLD:
        return DetectionResult(
            vendor="unknown",
            display_name="Unrecognised vendor",
            confidence=best_score,
            scores=scores,
        )

    pack = library.get(best)
    assert pack is not None
    return DetectionResult(
        vendor=best,
        display_name=pack.display_name,
        confidence=best_score,
        scores=scores,
        matched_signatures=matches[best],
    )
