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


def main() -> int:
    base = Settings()
    library = RulePackLibrary(base.knowledge_dir)
    index = KnowledgeIndex(library, base.embedding_model)
    index.build()

    sample = (base.samples_dir / "mikrotik_branch_router.rsc").read_text(encoding="utf-8")
    unknowns = parse(sample, library.get("generic")).unknown_commands
    commands = [u.raw for u in unknowns]
    examples = index.examples_for_prompt(commands[0], "unknown", base.retrieval_top_k)

    print(f"{len(commands)} commands · one batch per model\n")
    print(f"{'model':<24} {'time':>8} {'correct':>9} {'wrong':>7} {'declined':>9} {'missed':>7}")
    print("-" * 70)

    results = []
    for model in CANDIDATES:
        settings = base.model_copy(update={"llm_model": model, "llm_max_batch": 16})
        provider = OpenAICompatProvider(settings)

        started = time.perf_counter()
        proposals = provider.interpret("unknown", commands, examples)
        elapsed = time.perf_counter() - started

        by_index = {p.index: p for p in proposals}
        correct = wrong = declined_ok = missed = 0

        for i, command in enumerate(commands):
            want_param, want_value = ANSWER_KEY.get(command, (None, None))
            got = by_index.get(i)

            if got is None:
                if want_param is None:
                    declined_ok += 1   # correctly said nothing
                else:
                    missed += 1        # should have mapped it
            elif want_param is None:
                wrong += 1             # invented a mapping where none exists
            elif got.parameter == want_param and got.value == want_value:
                correct += 1
            else:
                wrong += 1

        results.append((model, elapsed, correct, wrong, declined_ok, missed))
        print(f"{model:<24} {elapsed:>7.1f}s {correct:>9} {wrong:>7} {declined_ok:>9} {missed:>7}")

        for i, command in enumerate(commands):
            want_param, _ = ANSWER_KEY.get(command, (None, None))
            got = by_index.get(i)
            if got is not None and want_param is not None and got.parameter != want_param:
                print(f"    wrong: {command[:44]:<44} -> {got.parameter} (want {want_param})")
            elif got is not None and want_param is None:
                print(f"    invented: {command[:42]:<42} -> {got.parameter}")

    print()
    scored = sorted(results, key=lambda r: (-(r[2] + r[4]), r[1]))
    best = scored[0]
    print(f"Best accuracy: {best[0]}  ({best[2] + best[4]}/{len(commands)} right, {best[1]:.1f}s)")
    fastest = min(results, key=lambda r: r[1])
    print(f"Fastest      : {fastest[0]}  ({fastest[1]:.1f}s, {fastest[2] + fastest[4]}/{len(commands)} right)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
