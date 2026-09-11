"""Reset the platform to a clean, pre-demo state.

Removes every administrator-learned mapping and clears the scan history, so a
demo can be re-run from the beginning. Rules that shipped in the box are left
untouched -- only knowledge added through the Teach-AI screen is removed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.core.config import get_settings  # noqa: E402


def main() -> int:
    settings = get_settings()
    removed = 0

    for path in sorted(settings.knowledge_dir.glob("*.json")):
        pack = json.loads(path.read_text(encoding="utf-8"))
        rules = pack.get("rules", [])
        kept = [r for r in rules if r.get("origin", "builtin") != "learned"]
        if len(kept) != len(rules):
            removed += len(rules) - len(kept)
            pack["rules"] = kept
            path.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
            print(f"  {path.name}: removed {len(rules) - len(kept)} learned rule(s)")

    database = Path(settings.database_url.replace("sqlite:///", ""))
    if database.exists():
        try:
            database.unlink()
            print(f"  removed scan history and training audit ({database.name})")
        except PermissionError:
            # Windows holds the file open while the API server is running.
            # Emptying the tables achieves the same reset without a restart.
            from app.models.store import ConfigurationRecord, Store, TrainingEvent

            store = Store(settings.database_url)
            with store.session() as session:
                for model in (ConfigurationRecord, TrainingEvent):
                    session.query(model).delete()
                session.commit()
            print("  cleared scan history and training audit (server was holding the file)")

    for report in settings.report_dir.glob("*.pdf"):
        report.unlink()

    print(f"\nReset complete. {removed} learned mapping(s) removed; built-in rules untouched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
