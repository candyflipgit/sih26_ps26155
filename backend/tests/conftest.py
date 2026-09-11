"""Shared fixtures.

`client` runs the real FastAPI app against a throwaway copy of the data
directory with inference disabled, so API tests never touch the working
knowledge base, the real database, or a live model endpoint.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="session")
def _session_patch():
    patcher = pytest.MonkeyPatch()
    yield patcher
    patcher.undo()


@pytest.fixture(scope="session")
def client(tmp_path_factory, _session_patch):
    from fastapi.testclient import TestClient

    import app.main as main
    from app.core.config import Settings

    root = tmp_path_factory.mktemp("api")
    data = root / "data"
    shutil.copytree(DATA, data, ignore=shutil.ignore_patterns("*.db", "reports", "uploads"))
    for path in (data / "knowledge").glob("*.json"):
        pack = json.loads(path.read_text(encoding="utf-8"))
        pack["rules"] = [r for r in pack.get("rules", []) if r.get("origin", "builtin") != "learned"]
        path.write_text(json.dumps(pack), encoding="utf-8")

    settings = Settings(
        data_dir=data,
        upload_dir=data / "uploads",
        report_dir=data / "reports",
        database_url=f"sqlite:///{(root / 'test.db').as_posix()}",
        llm_api_key="",  # never reach a live model from the test suite
        llm_base_url="https://inference.invalid/v1",
    )
    settings.ensure_directories()
    _session_patch.setattr(main, "get_settings", lambda: settings)

    with TestClient(main.app) as test_client:
        yield test_client
