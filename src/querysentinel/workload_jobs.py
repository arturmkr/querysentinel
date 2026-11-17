from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from querysentinel.models import SyntheticWorkloadJob
from querysentinel.schemas import JobStatus, SyntheticWorkloadRequest


def enqueue_workload(session: Session, request: SyntheticWorkloadRequest) -> SyntheticWorkloadJob:
    job = SyntheticWorkloadJob(
        target_id=request.target_id,
        query_count=request.queries,
        rounds=request.rounds,
        fresh=request.fresh,
        status=JobStatus.QUEUED,
    )
    session.add(job)
    session.commit()
    return job


def claim_workload(session: Session) -> SyntheticWorkloadJob | None:
    job = session.scalar(
        select(SyntheticWorkloadJob)
        .where(SyntheticWorkloadJob.status == JobStatus.QUEUED)
        .order_by(SyntheticWorkloadJob.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if job is None:
        session.rollback()
        return None
    job.status = JobStatus.RUNNING
    job.started_at = datetime.now(UTC)
    job.error = None
    session.commit()
    return job


def complete_workload(
    session: Session, job: SyntheticWorkloadJob, *, generated: bool, succeeded: int, failed: int
) -> None:
    job.generated = generated
    job.succeeded = succeeded
    job.failed = failed
    job.status = JobStatus.COMPLETED
    job.completed_at = datetime.now(UTC)
    session.commit()


def fail_workload(session: Session, job: SyntheticWorkloadJob, error: str) -> None:
    job.status = JobStatus.FAILED
    job.error = error[:4000]
    job.completed_at = datetime.now(UTC)
    session.commit()
