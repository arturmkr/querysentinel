from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from querysentinel.schemas import (
    FindingStatus,
    InvestigationStatus,
    JobSource,
    JobStatus,
    Severity,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    target_id: Mapped[str] = mapped_column(String(63), index=True)
    status: Mapped[str] = mapped_column(String(16), default=JobStatus.QUEUED, index=True)
    source: Mapped[str] = mapped_column(String(16), default=JobSource.MANUAL)
    scheduling_window: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)

    observations: Mapped[list[FindingObservation]] = relationship(back_populates="scan")

    __table_args__ = (
        UniqueConstraint("target_id", "scheduling_window", name="uq_job_target_window"),
    )


class SyntheticWorkloadJob(Base):
    __tablename__ = "synthetic_workload_jobs"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    target_id: Mapped[str] = mapped_column(String(63), index=True)
    status: Mapped[str] = mapped_column(String(16), default=JobStatus.QUEUED, index=True)
    query_count: Mapped[int] = mapped_column(Integer)
    rounds: Mapped[int] = mapped_column(Integer)
    fresh: Mapped[bool] = mapped_column(Boolean, default=False)
    generated: Mapped[bool] = mapped_column(Boolean, default=False)
    succeeded: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)


class QueryCounterSnapshot(Base):
    __tablename__ = "query_counter_snapshots"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(String(63), index=True)
    dbid: Mapped[int] = mapped_column(BigInteger)
    userid: Mapped[int] = mapped_column(BigInteger)
    queryid: Mapped[int] = mapped_column(BigInteger)
    toplevel: Mapped[bool] = mapped_column(Boolean)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    query_text: Mapped[str] = mapped_column(Text)
    calls: Mapped[int] = mapped_column(BigInteger)
    total_exec_time_ms: Mapped[float] = mapped_column(Float)
    rows: Mapped[int] = mapped_column(BigInteger)
    shared_blks_hit: Mapped[int] = mapped_column(BigInteger)
    shared_blks_read: Mapped[int] = mapped_column(BigInteger)
    temp_blks_read: Mapped[int] = mapped_column(BigInteger)
    temp_blks_written: Mapped[int] = mapped_column(BigInteger)
    stats_reset: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dealloc: Mapped[int | None] = mapped_column(BigInteger)
    pending_sample: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    counter_epoch_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "scan_id", "dbid", "userid", "queryid", "toplevel", name="uq_snapshot_identity"
        ),
        Index("ix_snapshot_lookup", "target_id", "fingerprint", "collected_at"),
    )


class QueryIntervalMetric(Base):
    __tablename__ = "query_interval_metrics"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(String(63), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    query_text: Mapped[str] = mapped_column(Text)
    interval_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    interval_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    calls: Mapped[int] = mapped_column(BigInteger)
    total_exec_time_ms: Mapped[float] = mapped_column(Float)
    mean_exec_time_ms: Mapped[float] = mapped_column(Float)
    rows: Mapped[int] = mapped_column(BigInteger)
    shared_blks_hit: Mapped[int] = mapped_column(BigInteger)
    shared_blks_read: Mapped[int] = mapped_column(BigInteger)
    temp_blks_read: Mapped[int] = mapped_column(BigInteger)
    temp_blks_written: Mapped[int] = mapped_column(BigInteger)
    compatible: Mapped[bool] = mapped_column(Boolean, default=True)
    incompatibility_reason: Mapped[str | None] = mapped_column(String(64))
    sample_scope: Mapped[str] = mapped_column(
        String(16), default="interval", server_default="interval"
    )
    username: Mapped[str | None] = mapped_column(Text)
    counter_epoch_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_interval_scan_fingerprint"),
        Index("ix_interval_history", "target_id", "fingerprint", "interval_end"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    target_id: Mapped[str] = mapped_column(String(63), index=True)
    query_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    # pg_stat_statements normalizes constants, so this is the useful statement shape rather
    # than a copy of application data.  Keeping it on the finding makes every alert actionable
    # even after interval metrics have been removed by retention.
    query_text: Mapped[str] = mapped_column(Text)
    anomaly_type: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16), default=Severity.MEDIUM)
    status: Mapped[str] = mapped_column(String(16), default=FindingStatus.OPEN, index=True)
    summary: Mapped[str] = mapped_column(Text)
    current_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_reason: Mapped[str | None] = mapped_column(String(32))

    observations: Mapped[list[FindingObservation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    investigations: Mapped[list[Investigation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "target_id", "query_fingerprint", "anomaly_type", name="uq_finding_identity"
        ),
    )


class ErrorLogCheckpoint(Base):
    __tablename__ = "error_log_checkpoints"

    target_id: Mapped[str] = mapped_column(String(63), primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    positions: Mapped[dict[str, list[int]]] = mapped_column(JSON)


class SlowQueryObservation(Base):
    __tablename__ = "slow_query_observations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    target_id: Mapped[str] = mapped_column(String(63))
    query_id: Mapped[int] = mapped_column(BigInteger)
    username: Mapped[str] = mapped_column(Text)
    client: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_slow_query_source_lookup", "target_id", "query_id", "username", "observed_at"),
        Index("ix_slow_query_retention", "target_id", "observed_at"),
    )


class FindingObservation(Base):
    __tablename__ = "finding_observations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)

    finding: Mapped[Finding] = relationship(back_populates="observations")
    scan: Mapped[ScanJob] = relationship(back_populates="observations")

    __table_args__ = (UniqueConstraint("finding_id", "scan_id", name="uq_observation_scan"),)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), default=InvestigationStatus.FAILED_OR_SKIPPED)
    model_name: Mapped[str | None] = mapped_column(String(128))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="investigations")


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    event: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(32))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(Text)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "finding_id", "scan_id", "event", "channel", "attempt", name="uq_delivery_attempt"
        ),
    )
