"""Persistence.

SQLite through SQLAlchemy. A prototype does not need a database server, and
running one would add an operational dependency without changing anything a
reviewer can see. The ORM layer means the same models point at PostgreSQL by
changing one URL if this ever outgrows a single file.

Two things are worth persisting. Scan history, so a device can be compared
against its previous assessment, and the training audit trail, so every learned
mapping records who approved it and when. The second is the more important:
knowledge that changes how future devices are judged must be attributable.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ConfigurationRecord(Base):
    """One analysed configuration, with its full result retained."""

    __tablename__ = "configurations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(64), index=True)
    vendor_display: Mapped[str] = mapped_column(String(128), default="")
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)

    framework: Mapped[str] = mapped_column(String(32), default="ALL")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    coverage: Mapped[float] = mapped_column(Float, default=0.0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    unknown: Mapped[int] = mapped_column(Integer, default=0)
    critical_failures: Mapped[int] = mapped_column(Integer, default=0)

    # The raw configuration is kept so a finding can always be re-derived, and
    # so a re-scan after teaching a mapping needs no re-upload.
    raw_config: Mapped[str] = mapped_column(Text)
    result: Mapped[dict[str, Any]] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class TrainingEvent(Base):
    """An administrator's decision about an unrecognised command.

    This is the audit trail behind the learning loop. Because an approved
    mapping changes how every later device is judged, the record of who approved
    what has to outlive the session that produced it.
    """

    __tablename__ = "training_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vendor: Mapped[str] = mapped_column(String(64), index=True)
    command: Mapped[str] = mapped_column(Text)
    template: Mapped[str] = mapped_column(Text)
    parameter: Mapped[str] = mapped_column(String(128))
    value: Mapped[str] = mapped_column(String(128))
    value_rule: Mapped[str] = mapped_column(String(64))

    # What the model proposed, retained even when the administrator overrode it
    # -- the disagreement rate is the honest measure of the AI layer's quality.
    ai_parameter: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ai_value: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    accepted_ai_suggestion: Mapped[int] = mapped_column(Integer, default=0)

    approved_by: Mapped[str] = mapped_column(String(128), default="administrator")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Store:
    def __init__(self, url: str) -> None:
        self.engine = create_engine(url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self._session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def session(self) -> Session:
        return self._session()

    # --- configurations ----------------------------------------------------

    def save_analysis(self, result, raw_config: str) -> ConfigurationRecord:
        device = result.normalized.device
        summary = result.scan.summary

        record = ConfigurationRecord(
            id=result.config_id,
            filename=result.filename,
            vendor=result.detection.vendor,
            vendor_display=result.detection.display_name,
            hostname=device.hostname,
            model=device.model,
            os_version=device.os_version,
            serial_number=device.serial_number,
            framework=result.framework,
            score=summary.score,
            coverage=summary.coverage,
            passed=summary.passed,
            failed=summary.failed,
            unknown=summary.unknown,
            critical_failures=summary.failed_by_severity.critical,
            raw_config=raw_config,
            result=json.loads(result.model_dump_json()),
        )

        with self.session() as session:
            session.merge(record)  # re-analysing the same file updates in place
            session.commit()
        return record

    def get_analysis(self, config_id: str) -> ConfigurationRecord | None:
        with self.session() as session:
            return session.get(ConfigurationRecord, config_id)

    def list_analyses(self, limit: int = 50) -> list[ConfigurationRecord]:
        with self.session() as session:
            statement = (
                select(ConfigurationRecord)
                .order_by(ConfigurationRecord.created_at.desc())
                .limit(limit)
            )
            return list(session.scalars(statement))

    def fleet_summary(self) -> dict[str, Any]:
        """Aggregate posture across every analysed device, for the dashboard."""
        with self.session() as session:
            rows = list(session.scalars(select(ConfigurationRecord)))
            if not rows:
                return {
                    "devices": 0, "average_score": 0.0, "total_failed": 0,
                    "critical_failures": 0, "vendors": {},
                }

            vendors: dict[str, int] = {}
            for row in rows:
                vendors[row.vendor_display or row.vendor] = (
                    vendors.get(row.vendor_display or row.vendor, 0) + 1
                )

            return {
                "devices": len(rows),
                "average_score": round(sum(r.score for r in rows) / len(rows), 1),
                "total_failed": sum(r.failed for r in rows),
                "critical_failures": sum(r.critical_failures for r in rows),
                "vendors": vendors,
            }

    # --- training ----------------------------------------------------------

    def record_training(self, event: TrainingEvent) -> TrainingEvent:
        with self.session() as session:
            session.add(event)
            session.commit()
            session.refresh(event)
        return event

    def list_training(self, limit: int = 100) -> list[TrainingEvent]:
        with self.session() as session:
            statement = (
                select(TrainingEvent).order_by(TrainingEvent.created_at.desc()).limit(limit)
            )
            return list(session.scalars(statement))

    def training_stats(self) -> dict[str, Any]:
        """How often the model's proposal survived administrator review.

        Reported rather than assumed. A system that claims its AI is accurate
        without measuring the correction rate is claiming something it does not
        know.
        """
        with self.session() as session:
            total = session.scalar(select(func.count(TrainingEvent.id))) or 0
            with_suggestion = session.scalar(
                select(func.count(TrainingEvent.id)).where(TrainingEvent.ai_parameter.isnot(None))
            ) or 0
            accepted = session.scalar(
                select(func.count(TrainingEvent.id)).where(
                    TrainingEvent.accepted_ai_suggestion == 1
                )
            ) or 0

        return {
            "total_mappings": total,
            "ai_assisted": with_suggestion,
            "ai_accepted": accepted,
            "ai_corrected": with_suggestion - accepted,
            "acceptance_rate": (
                round(100.0 * accepted / with_suggestion, 1) if with_suggestion else None
            ),
        }
