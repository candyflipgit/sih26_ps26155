"""Benchmark the available inference models on the real unknown-command task.

Demo latency matters as much as accuracy here: a seven-second pause while the
training queue loads is dead air on a two-minute video. This measures both on
the same fifteen MikroTik commands, against a hand-written answer key.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.ai.provider import OpenAICompatProvider  # noqa: E402
from app.ai.vectorstore import KnowledgeIndex  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.parsers.engine import parse  # noqa: E402
from app.parsers.rulepack import RulePackLibrary  # noqa: E402

# What a network engineer would map each command to. `None` means no canonical
# parameter covers it, so declining is the correct answer, not a failure.
ANSWER_KEY: dict[str, tuple[str | None, object]] = {
    "/ip ssh set strong-crypto=yes": ("management.ssh.strong_crypto", True),
    "/ip ssh set allow-none-crypto=no": (None, None),
    "/ip ssh set host-key-size=4096": (None, None),
    "/ip service set telnet disabled=no port=23": ("management.telnet.enabled", True),
    "/ip service set ftp disabled=yes": (None, None),
    "/ip service set www disabled=no port=80": ("management.http.enabled", True),
    "/ip service set ssh disabled=no port=22": ("management.ssh.enabled", True),
    "/ip service set www-ssl disabled=yes": ("management.https.enabled", False),
    "/ip service set api disabled=yes": (None, None),
    "/ip service set winbox address=10.99.0.0/24": ("access.management_acl.enabled", True),
    "/system ntp client set enabled=yes primary-ntp=10.50.4.10": ("time.ntp.enabled", True),
    "/system logging action set 1 remote=10.50.4.20 target=remote": (
        "logging.remote_syslog.enabled", True,
    ),
    "/snmp set enabled=yes contact=noc@corp.example.net location=Branch07": ("snmp.enabled", True),
    "/snmp community set 0 name=public addresses=10.50.4.0/24 read-access=yes": (
        "snmp.default_community.present", True,
    ),
    "/user set 0 name=admin group=full": ("authentication.default_accounts.present", True),
}

CANDIDATES = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "qwen/qwen3.6-27b",
]

# Ablations for the research-derived changes, so each is measured on this task
# rather than assumed to transfer from the papers that motivated it.
ABLATIONS = [
    ("baseline (1 sample, no context)", {"llm_samples": 1}, False),
    ("+ block context", {"llm_samples": 1}, True),
    ("+ self-consistency (3)", {"llm_samples": 3}, True),
]


def score(proposals, commands, verbose=False):
    """Score one run against the answer key.

    Declining a command with no correct mapping counts as success, not as a
    miss. A scorer that penalised silence would reward a model for guessing.
    """
    by_index = {p.index: p for p in proposals}
    correct = wrong = declined_ok = missed = 0
    notes: list[str] = []

    for i, command in enumerate(commands):
        want_param, want_value = ANSWER_KEY.get(command, (None, None))
        got = by_index.get(i)

        if got is None:
            if want_param is None:
                declined_ok += 1
            else:
                missed += 1
                notes.append(f"    missed:   {command[:44]:<44} (want {want_param})")
        elif want_param is None:
            wrong += 1
            notes.append(f"    invented: {command[:44]:<44} -> {got.parameter}")
        elif got.parameter == want_param and got.value == want_value:
            correct += 1
        else:
            wrong += 1
            notes.append(f"    wrong:    {command[:44]:<44} -> {got.parameter} (want {want_param})")

    if verbose:
        for n in notes:
            print(n)
    return correct, wrong, declined_ok, missed


def confidence_spread(proposals) -> str:
    """How much signal the confidence numbers actually carry.

    A run where every proposal scores 1.00 has a confidence field that cannot
    separate anything, which is the failure this project measured directly.
    """
    if not proposals:
        return "n/a"
    values = sorted(p.confidence for p in proposals)
    distinct = len(set(values))
    return f"{values[0]:.2f}-{values[-1]:.2f} ({distinct} distinct)"


def main() -> int:
    base = Settings()
    library = RulePackLibrary(base.knowledge_dir)
    index = KnowledgeIndex(library, base.embedding_model)
    index.build()

    sample = (base.samples_dir / "mikrotik_branch_router.rsc").read_text(encoding="utf-8")
    unknowns = parse(sample, library.get("generic")).unknown_commands
    commands = [u.raw for u in unknowns]
    contexts = [u.context for u in unknowns]
    examples = index.examples_for_prompt(commands[0], "unknown", base.retrieval_top_k)
    total = len(commands)

    header = f"{'':<34} {'time':>7} {'right':>7} {'wrong':>7} {'missed':>7}  confidence"

    print(f"=== MODELS (single sample, with context) · {total} commands ===\n")
    print(header)
    print("-" * 86)

    results = []
    for model in CANDIDATES:
        settings = base.model_copy(
            update={"llm_model": model, "llm_max_batch": 16, "llm_samples": 1}
        )
        started = time.perf_counter()
        proposals = OpenAICompatProvider(settings).interpret(
            "unknown", commands, examples, contexts
        )
        elapsed = time.perf_counter() - started
        c, w, d, m = score(proposals, commands)
        results.append((model, elapsed, c + d))
        print(
            f"{model:<34} {elapsed:>6.1f}s {c + d:>7} {w:>7} {m:>7}"
            f"  {confidence_spread(proposals)}"
        )

    print(f"\n=== ABLATIONS on {base.llm_model} ===\n")
    print(header)
    print("-" * 86)

    for label, overrides, use_context in ABLATIONS:
        settings = base.model_copy(update={"llm_max_batch": 16, **overrides})
        started = time.perf_counter()
        proposals = OpenAICompatProvider(settings).interpret(
            "unknown", commands, examples, contexts if use_context else None
        )
        elapsed = time.perf_counter() - started
        c, w, d, m = score(proposals, commands, verbose=True)
        print(
            f"{label:<34} {elapsed:>6.1f}s {c + d:>7} {w:>7} {m:>7}"
            f"  {confidence_spread(proposals)}"
        )

    print()
    best = max(results, key=lambda r: (r[2], -r[1]))
    print(f"Best model: {best[0]} ({best[2]}/{total} right, {best[1]:.1f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
