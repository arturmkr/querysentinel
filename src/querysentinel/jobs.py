from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from querysentinel.models import ScanJob
from querysentinel.schemas import JobSource, JobStatus

ACTIVE_STATUSES = (JobStatus.QUEUED, JobStatus.RUNNING)


class ActiveScanError(Exception):
    def __init__(self, job: ScanJob) -> None:
        self.job = job
        super().__init__(f"target {job.target_id} already has active scan {job.id}")


def active_job_query(target_id: str) -> Select[tuple[ScanJob]]:
    return (
        select(ScanJob)
        .where(ScanJob.target_id == target_id, ScanJob.status.in_(ACTIVE_STATUSES))
        .order_by(ScanJob.created_at)
    )


def enqueue_job(
    session: Session,
    target_id: str,
    source: JobSource,
    scheduling_window: datetime | None = None,
) -> ScanJob:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:target_id, 0))"),
            {"target_id": target_id},
        )
    existing = session.scalar(active_job_query(target_id).with_for_update())
    if existing:
        raise ActiveScanError(existing)
    job = ScanJob(
        target_id=target_id,
        source=source,
        scheduling_window=scheduling_window,
        status=JobStatus.QUEUED,
    )
    session.add(job)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        duplicate = session.scalar(
            select(ScanJob).where(
                ScanJob.target_id == target_id,
                ScanJob.scheduling_window == scheduling_window,
            )
        )
        if duplicate:
            return duplicate
        raise
    return job


def recover_expired_jobs(session: Session, max_attempts: int) -> int:
    now = datetime.now(UTC)
    jobs = session.scalars(
        select(ScanJob).where(
            ScanJob.status == JobStatus.RUNNING,
            ScanJob.lease_expires_at < now,
        )
    ).all()
    for job in jobs:
        if job.attempts >= max_attempts:
            job.status = JobStatus.FAILED
            job.completed_at = now
            job.error = "worker lease expired and retry limit was reached"
        else:
            job.status = JobStatus.QUEUED
            job.lease_expires_at = None
            job.next_attempt_at = now + timedelta(seconds=2**job.attempts)
            job.error = "worker lease expired; queued for retry"
    session.commit()
    return len(jobs)


def claim_job(session: Session, lease_seconds: int, max_attempts: int) -> ScanJob | None:
    recover_expired_jobs(session, max_attempts)
    now = datetime.now(UTC)
    running = aliased(ScanJob)
    queued = session.scalar(
        select(ScanJob)
        .where(
            ScanJob.status == JobStatus.QUEUED,
            ScanJob.attempts < max_attempts,
            ScanJob.next_attempt_at <= now,
        )
        .where(
            ~select(running.id)
            .where(
                running.target_id == ScanJob.target_id,
                running.status == JobStatus.RUNNING,
                or_(running.lease_expires_at.is_(None), running.lease_expires_at >= now),
            )
            .exists()
        )
        .order_by(ScanJob.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if queued is None:
        session.rollback()
        return None
    queued.status = JobStatus.RUNNING
    queued.started_at = queued.started_at or now
    queued.heartbeat_at = now
    queued.lease_expires_at = now + timedelta(seconds=lease_seconds)
    queued.attempts += 1
    queued.error = None
    session.commit()
    return queued


def heartbeat(session: Session, job_id, lease_seconds: int) -> None:
    now = datetime.now(UTC)
    session.execute(
        update(ScanJob)
        .where(ScanJob.id == job_id, ScanJob.status == JobStatus.RUNNING)
        .values(
            heartbeat_at=now,
            lease_expires_at=now + timedelta(seconds=lease_seconds),
        )
    )
    session.commit()


def complete_job(session: Session, job: ScanJob) -> None:
    job.status = JobStatus.COMPLETED
    job.completed_at = datetime.now(UTC)
    job.lease_expires_at = None
    session.commit()


def fail_job(session: Session, job: ScanJob, error: str, max_attempts: int) -> None:
    job.error = error[:4000]
    job.lease_expires_at = None
    if job.attempts < max_attempts:
        job.status = JobStatus.QUEUED
        job.next_attempt_at = datetime.now(UTC) + timedelta(seconds=2**job.attempts)
    else:
        job.status = JobStatus.FAILED
        job.completed_at = datetime.now(UTC)
    session.commit()
