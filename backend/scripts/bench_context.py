"""Ablation: does supplying the enclosing configuration block actually help?

CAIP (arXiv:2411.14283) reports a large gain from giving the model the context
around a configuration line. That claim is worth testing on this system rather
than assuming it transfers, and the MikroTik sample is a poor test of it because
RouterOS commands are self-contained -- `/ip service set telnet disabled=no`
means the same thing wherever it appears.

The case that actually depends on context is a block-structured vendor. In
FortiOS, `set status enable` is meaningless in isolation: under
`config log syslogd setting` it enables remote syslog, under `config system
snmp sysinfo` it enables the SNMP agent. Those are different security controls
from identical text. This script scores exactly those commands with and without
the block, which isolates the variable.

Also reports how much the confidence field can discriminate, since a confidence
that is always ~1.0 cannot gate anything.
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
from app.parsers.rulepack import RulePackLibrary  # noqa: E402

# (command, enclosing block, expected parameter, expected value)
# Every command here is ambiguous without its block.
CASES = [
    ("set status enable", "config log syslogd setting", "logging.remote_syslog.enabled", True),
    ("set status enable", "config system snmp sysinfo", "snmp.enabled", True),
    ("set status enable", "config log disk setting", "logging.local.enabled", True),
    ("set status enable", "config system password-policy", None, None),
    ("set minimum-length 12", "config system password-policy",
     "authentication.password.min_length", 12),
    ("set name \"public\"", "config system snmp community / edit 1",
     "snmp.default_community.present", True),
    ("set server \"10.50.4.20\"", "config log syslogd setting", None, None),
    ("edit \"admin\"", "config system admin", "authentication.default_accounts.present", True),
    ("set trusthost1 10.99.0.0 255.255.255.0", "config system admin / edit \"admin\"",
     "access.management_acl.enabled", True),
    ("set admintimeout 10", "config system global", "access.idle_timeout.seconds", 600),
]


def score(proposals, cases):
    by_index = {p.index: p for p in proposals}
    right = wrong = 0
    notes = []
    for i, (command, block, want_param, want_value) in enumerate(cases):
        got = by_index.get(i)
        if got is None:
            if want_param is None:
                right += 1
            else:
                wrong += 1
                notes.append(f"      missed   {command:<38} [{block[:30]}] want {want_param}")
        elif want_param is None:
            wrong += 1
            notes.append(f"      invented {command:<38} [{block[:30]}] -> {got.parameter}")
        elif got.parameter == want_param and got.value == want_value:
            right += 1
        else:
            wrong += 1
            notes.append(
                f"      wrong    {command:<38} [{block[:30]}] -> {got.parameter}={got.value}"
            )
    return right, wrong, notes


def spread(proposals) -> str:
    if not proposals:
        return "n/a"
    vals = sorted(p.confidence for p in proposals)
    return f"{vals[0]:.2f}-{vals[-1]:.2f}, {len(set(vals))} distinct"


def main() -> int:
    base = Settings()
    library = RulePackLibrary(base.knowledge_dir)
    index = KnowledgeIndex(library, base.embedding_model)
    index.build()

    commands = [c for c, _, _, _ in CASES]
    contexts = [b for _, b, _, _ in CASES]
    examples = index.examples_for_prompt(commands[0], "fortinet_fortios", base.retrieval_top_k)
    total = len(CASES)

    runs = [
        ("without block context", {"llm_samples": 1}, None),
        ("with block context", {"llm_samples": 1}, contexts),
        ("with context + 3-sample vote", {"llm_samples": 3}, contexts),
    ]

    print(f"{total} deliberately context-dependent FortiOS commands\n")
    print(f"{'':<32} {'time':>7} {'right':>7} {'wrong':>7}  confidence spread")
    print("-" * 78)

    for label, overrides, ctx in runs:
        settings = base.model_copy(update={"llm_max_batch": 16, **overrides})
        started = time.perf_counter()
        proposals = OpenAICompatProvider(settings).interpret(
            "fortinet_fortios", commands, examples, ctx
        )
        elapsed = time.perf_counter() - started
        right, wrong, notes = score(proposals, CASES)
        print(f"{label:<32} {elapsed:>6.1f}s {right:>7} {wrong:>7}  {spread(proposals)}")
        for n in notes:
            print(n)
        # Pace the runs so a free-tier rate limit does not masquerade as a result.
        time.sleep(8)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
