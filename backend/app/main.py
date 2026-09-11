"""FastAPI application.

The API is deliberately thin. Every endpoint delegates to the analysis engine or
the store; no compliance logic, no parsing and no prompting lives here, so the
security-relevant code stays in modules that are unit-testable without an HTTP
client.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.compliance.remediation import RemediationLibrary, RemediationPlan
from app.core.config import Settings, get_settings
from app.models.store import Store, TrainingEvent
from app.reports.generator import ReportBuilder
from app.schema.parameters import PARAMETERS, PARAMETER_INDEX, coerce_value
from app.services.analysis import AnalysisEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("netbaseline")

# Uploaded configurations are text; this ceiling keeps a stray binary from being
# read into memory.
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    engine = AnalysisEngine(settings)
    state["settings"] = settings
    state["engine"] = engine
    state["store"] = Store(settings.database_url)
    state["remediation"] = RemediationLibrary(settings.data_dir / "rules" / "remediation.json")
    state["reports"] = ReportBuilder(state["remediation"])

    # Load the embedding model now so the first analysis is not the one that
    # pays for it. In a live demo that request is the one being watched.
    engine.warm_up()
    logger.info(
        "Ready. %d controls, %d rules, inference %s",
        len(engine.catalog.rules),
        sum(len(p.rules) for p in engine.library.all()),
        engine.provider.name if engine.provider.available else "unavailable (retrieval-only)",
    )
    yield
    state.clear()


app = FastAPI(
    title="NetBaseline AI",
    description=(
        "AI-augmented, vendor-agnostic network security compliance auditor. "
        "The AI layer interprets vendor syntax; a deterministic engine decides compliance."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    # The frontend is served separately during development.
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_engine() -> AnalysisEngine:
    return state["engine"]


def get_store() -> Store:
    return state["store"]


def get_config() -> Settings:
    return state["settings"]


# --- request/response models ------------------------------------------------

class AnalyzeTextRequest(BaseModel):
    text: str
    filename: str = "pasted-configuration.cfg"
    framework: str = "ALL"


class TeachRequest(BaseModel):
    """An administrator's decision on one unrecognised command."""

    command: str
    parameter: str
    value: Any
    vendor: str = "generic"
    approved_by: str = "administrator"
    config_id: str | None = None
    # What the model proposed, so agreement can be measured honestly.
    ai_parameter: str | None = None
    ai_value: Any = None
    ai_confidence: float | None = None


class TeachResponse(BaseModel):
    rule_id: str
    template: str
    parameter: str
    value_rule: str
    vendor: str
    message: str
    accepted_ai_suggestion: bool
    knowledge: dict[str, Any] = Field(default_factory=dict)


# --- meta -------------------------------------------------------------------

@app.get("/api/v1/health")
def health(engine: AnalysisEngine = Depends(get_engine)) -> dict[str, Any]:
    return {
        "status": "ok",
        "llm_available": engine.provider.available,
        "llm_backend": engine.provider.name,
    }


@app.get("/api/v1/meta")
def meta(
    engine: AnalysisEngine = Depends(get_engine),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_config),
) -> dict[str, Any]:
    """Everything the UI needs to render its dropdowns and status panels."""
    return {
        "app_name": settings.app_name,
        "knowledge": engine.knowledge_summary(),
        "parameters": [p.model_dump() for p in PARAMETERS],
        "controls": [
            {
                "id": r.id, "title": r.title, "severity": r.severity.value,
                "parameter": r.parameter, "frameworks": r.frameworks,
                "description": r.description, "impact": r.impact,
            }
            for r in engine.catalog.rules
        ],
        "training_stats": store.training_stats(),
        "ai_policy": {
            "autoaccept": settings.ai_autoaccept,
            "floor_threshold": settings.ai_floor_threshold,
            "accept_threshold": settings.ai_accept_threshold,
            "explanation": (
                "Model proposals are shown with their confidence but marked for review. "
                "A control backed only by an unreviewed AI reading is reported as "
                "undetermined, never as a pass or a failure, until an administrator "
                "approves the mapping."
            ),
        },
    }


@app.get("/api/v1/samples")
def samples(settings: Settings = Depends(get_config)) -> list[dict[str, Any]]:
    """Bundled configurations, so the platform can be tried with no files to hand."""
    out = []
    for path in sorted(settings.samples_dir.glob("*")):
        if path.suffix.lower() in {".cfg", ".conf", ".txt", ".rsc", ".json"}:
            out.append({
                "name": path.name,
                "size": path.stat().st_size,
                "lines": len(path.read_text(encoding="utf-8", errors="replace").splitlines()),
            })
    return out


# --- analysis ---------------------------------------------------------------

def _run(text: str, filename: str, framework: str) -> dict[str, Any]:
    engine: AnalysisEngine = state["engine"]
    store: Store = state["store"]
    result = engine.analyze(text, filename, framework)
    store.save_analysis(result, text)
    return result.model_dump(mode="json")


@app.post("/api/v1/configs/upload")
async def upload(
    file: UploadFile = File(...),
    framework: str = "ALL",
) -> dict[str, Any]:
    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Configuration exceeds {MAX_UPLOAD_BYTES // 1024 // 1024} MB")
    if not payload.strip():
        raise HTTPException(400, "The uploaded file is empty")

    text = payload.decode("utf-8", errors="replace")
    return _run(text, file.filename or "upload.cfg", framework)


@app.post("/api/v1/configs/analyze")
def analyze_text(request: AnalyzeTextRequest) -> dict[str, Any]:
    if not request.text.strip():
        raise HTTPException(400, "No configuration text supplied")
    return _run(request.text, request.filename, request.framework)


@app.post("/api/v1/samples/{name}/analyze")
def analyze_sample(
    name: str, framework: str = "ALL", settings: Settings = Depends(get_config)
) -> dict[str, Any]:
    # Resolve inside the samples directory so a crafted name cannot escape it.
    path = (settings.samples_dir / name).resolve()
    if not path.is_file() or settings.samples_dir.resolve() not in path.parents:
        raise HTTPException(404, f"No bundled sample named {name!r}")
    return _run(path.read_text(encoding="utf-8", errors="replace"), name, framework)


@app.get("/api/v1/analyses")
def list_analyses(store: Store = Depends(get_store)) -> dict[str, Any]:
    records = store.list_analyses()
    return {
        "fleet": store.fleet_summary(),
        "devices": [
            {
                "config_id": r.id, "filename": r.filename, "hostname": r.hostname,
                "vendor": r.vendor, "vendor_display": r.vendor_display, "model": r.model,
                "serial_number": r.serial_number, "os_version": r.os_version,
                "framework": r.framework, "score": r.score, "coverage": r.coverage,
                "passed": r.passed, "failed": r.failed, "unknown": r.unknown,
                "critical_failures": r.critical_failures,
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ],
    }


@app.get("/api/v1/analyses/{config_id}")
def get_analysis(config_id: str, store: Store = Depends(get_store)) -> dict[str, Any]:
    record = store.get_analysis(config_id)
    if record is None:
        raise HTTPException(404, "No analysis with that id")
    return record.result


@app.post("/api/v1/analyses/{config_id}/rescan")
def rescan(
    config_id: str, framework: str = "ALL", store: Store = Depends(get_store)
) -> dict[str, Any]:
    """Re-run an existing configuration against current knowledge.

    This is what closes the training loop: after approving a mapping, the same
    file is re-analysed and the previously unrecognised command now resolves
    deterministically, with no re-upload and no restart.
    """
    record = store.get_analysis(config_id)
    if record is None:
        raise HTTPException(404, "No analysis with that id")
    return _run(record.raw_config, record.filename, framework)


# --- findings and remediation ----------------------------------------------

@app.get("/api/v1/analyses/{config_id}/remediation/{rule_id}")
def remediation_for(config_id: str, rule_id: str, store: Store = Depends(get_store)) -> RemediationPlan:
    record = store.get_analysis(config_id)
    if record is None:
        raise HTTPException(404, "No analysis with that id")

    finding = next(
        (f for f in record.result.get("scan", {}).get("findings", []) if f["rule_id"] == rule_id),
        None,
    )
    if finding is None:
        raise HTTPException(404, "No such finding in that analysis")

    plan = state["remediation"].plan_for(finding.get("remediation_id"), record.vendor)
    if plan is None:
        raise HTTPException(404, "No remediation template for that control")
    return plan


# --- training ---------------------------------------------------------------

@app.get("/api/v1/training/events")
def training_events(store: Store = Depends(get_store)) -> dict[str, Any]:
    return {
        "stats": store.training_stats(),
        "events": [
            {
                "id": e.id, "vendor": e.vendor, "command": e.command, "template": e.template,
                "parameter": e.parameter, "value": e.value, "value_rule": e.value_rule,
                "ai_parameter": e.ai_parameter, "ai_confidence": e.ai_confidence,
                "accepted_ai_suggestion": bool(e.accepted_ai_suggestion),
                "approved_by": e.approved_by, "created_at": e.created_at.isoformat(),
            }
            for e in store.list_training()
        ],
    }


@app.post("/api/v1/training/approve", response_model=TeachResponse)
def approve_mapping(
    request: TeachRequest,
    engine: AnalysisEngine = Depends(get_engine),
    store: Store = Depends(get_store),
) -> TeachResponse:
    """Approve a mapping and make it active immediately.

    The rule is written into the vendor's pack on disk and the in-process
    library reloads, so the next scan recognises the command without a restart,
    a redeployment, or any model retraining.
    """
    if request.parameter not in PARAMETER_INDEX:
        raise HTTPException(422, f"'{request.parameter}' is not a canonical security parameter")
    if not request.command.strip():
        raise HTTPException(422, "No command supplied")

    try:
        value = coerce_value(request.parameter, request.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    try:
        rule = engine.teach(
            request.vendor, request.command, request.parameter, value, request.approved_by
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    accepted = (
        request.ai_parameter == request.parameter
        and str(request.ai_value) == str(value)
        if request.ai_parameter
        else False
    )

    store.record_training(TrainingEvent(
        vendor=request.vendor,
        command=request.command,
        template=rule.template or "",
        parameter=request.parameter,
        value=str(value),
        value_rule=rule.value_rule,
        ai_parameter=request.ai_parameter,
        ai_value=None if request.ai_value is None else str(request.ai_value),
        ai_confidence=request.ai_confidence,
        accepted_ai_suggestion=1 if accepted else 0,
        approved_by=request.approved_by,
    ))

    return TeachResponse(
        rule_id=rule.id,
        template=rule.template or "",
        parameter=rule.parameter,
        value_rule=rule.value_rule,
        vendor=request.vendor,
        accepted_ai_suggestion=accepted,
        message=(
            f"Learned `{rule.template}`. This command, and any variant of it, is now "
            f"recognised deterministically on every future scan."
        ),
        knowledge=engine.knowledge_summary(),
    )


@app.get("/api/v1/knowledge")
def knowledge(engine: AnalysisEngine = Depends(get_engine)) -> dict[str, Any]:
    """Browsable view of every mapping the platform knows."""
    packs = []
    for pack in engine.library.all():
        packs.append({
            "vendor": pack.vendor,
            "display_name": pack.display_name,
            "os_family": pack.os_family,
            "block_style": pack.block_style.value,
            "rules": [
                {
                    "id": r.id, "parameter": r.parameter,
                    "pattern": r.template or r.regex, "value_rule": r.value_rule,
                    "description": r.description, "origin": r.origin.value,
                    "approved_by": r.approved_by, "approved_at": r.approved_at,
                }
                for r in pack.rules
            ],
            "defaults": [d.model_dump() for d in pack.defaults],
        })
    return {"packs": packs, "summary": engine.knowledge_summary()}


# --- reports ----------------------------------------------------------------

@app.post("/api/v1/reports/{config_id}")
def generate_report(
    config_id: str,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_config),
) -> dict[str, Any]:
    record = store.get_analysis(config_id)
    if record is None:
        raise HTTPException(404, "No analysis with that id")

    from app.services.analysis import AnalysisResult

    result = AnalysisResult.model_validate(record.result)
    destination = settings.report_dir / f"{config_id}.pdf"
    state["reports"].build(result, destination)

    return {
        "config_id": config_id,
        "filename": destination.name,
        "size_bytes": destination.stat().st_size,
        "download_url": f"/api/v1/reports/{config_id}/download",
    }


@app.get("/api/v1/reports/{config_id}/download")
def download_report(config_id: str, settings: Settings = Depends(get_config)) -> FileResponse:
    path = settings.report_dir / f"{config_id}.pdf"
    if not path.is_file():
        raise HTTPException(404, "Report has not been generated yet")

    record = state["store"].get_analysis(config_id)
    label = (record.hostname or config_id) if record else config_id
    return FileResponse(
        path, media_type="application/pdf", filename=f"compliance-report-{label}.pdf"
    )
