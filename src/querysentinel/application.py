from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from querysentinel.config import ProjectConfig, TargetConfig
from querysentinel.jobs import enqueue_job
from querysentinel.models import Finding, Investigation, ScanJob, SyntheticWorkloadJob
from querysentinel.schemas import (
    FindingDetail,
    FindingPage,
    FindingStatus,
    FindingSummary,
    InvestigationResult,
    InvestigationStatus,
    JobSource,
    JobStatus,
    QuerySource,
    ScanDetail,
    ScanPage,
    ScanResponse,
    Severity,
    SyntheticWorkloadPage,
    SyntheticWorkloadRequest,
    SyntheticWorkloadResponse,
    TargetResponse,
)
from querysentinel.workload_jobs import enqueue_workload


class ApplicationError(Exception):
    """An expected failure from a QuerySentinel application operation."""


class TargetNotFoundError(ApplicationError):
    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        super().__init__(f"target {target_id!r} was not found")


class TargetDisabledError(ApplicationError):
    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        super().__init__(f"target {target_id!r} is disabled")


class ScanNotFoundError(ApplicationError):
    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        super().__init__(f"scan {scan_id} was not found")


class FindingNotFoundError(ApplicationError):
    def __init__(self, finding_id: UUID) -> None:
        self.finding_id = finding_id
        super().__init__(f"finding {finding_id} was not found")


class SyntheticWorkloadNotFoundError(ApplicationError):
    def __init__(self, job_id: UUID) -> None:
        self.job_id = job_id
        super().__init__(f"synthetic workload {job_id} was not found")


class SyntheticWorkloadDisabledError(ApplicationError):
    def __init__(self, target_id: str) -> None:
        self.target_id = target_id
        super().__init__(f"synthetic workload is disabled for target {target_id!r}")


class WorkloadConfigurationError(ApplicationError):
    pass


def require_target(config: ProjectConfig, target_id: str) -> TargetConfig:
    target = config.target(target_id)
    if target is None:
        raise TargetNotFoundError(target_id)
    return target


def target_response(config: ProjectConfig, target: TargetConfig) -> TargetResponse:
    return TargetResponse(
        id=target.id,
        engine=target.engine,
        enabled=target.enabled,
        schedule=target.schedule or config.schedule.cron,
        synthetic_workload_enabled=target.synthetic_workload_enabled,
    )


def list_targets(config: ProjectConfig) -> list[TargetResponse]:
    return [target_response(config, target) for target in config.targets]


def get_target(config: ProjectConfig, target_id: str) -> TargetResponse:
    return target_response(config, require_target(config, target_id))


def scan_detail(job: ScanJob) -> ScanDetail:
    return ScanDetail(
        scan_id=job.id,
        target_id=job.target_id,
        status=JobStatus(job.status),
        source=JobSource(job.source),
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        attempts=job.attempts,
        error=job.error,
    )


def scan_response(job: ScanJob) -> ScanResponse:
    return ScanResponse(
        scan_id=job.id,
        target_id=job.target_id,
        status=JobStatus(job.status),
    )


def list_scans(
    session: Session,
    config: ProjectConfig,
    *,
    target_id: str | None = None,
    status: JobStatus | None = None,
    source: JobSource | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> ScanPage:
    query = select(ScanJob)
    if target_id is not None:
        require_target(config, target_id)
        query = query.where(ScanJob.target_id == target_id)
    if status is not None:
        query = query.where(ScanJob.status == status)
    if source is not None:
        query = query.where(ScanJob.source == source)
    if since is not None:
        query = query.where(ScanJob.created_at >= since)
    if until is not None:
        query = query.where(ScanJob.created_at <= until)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    jobs = session.scalars(
        query.order_by(ScanJob.created_at.desc(), ScanJob.id.desc()).limit(limit).offset(offset)
    ).all()
    return ScanPage(
        items=[scan_detail(job) for job in jobs],
        total=total,
        limit=limit,
        offset=offset,
    )


def start_scan(
    session: Session,
    config: ProjectConfig,
    target_id: str,
    *,
    source: JobSource = JobSource.MANUAL,
) -> ScanResponse:
    target = require_target(config, target_id)
    if not target.enabled:
        raise TargetDisabledError(target_id)
    return scan_response(enqueue_job(session, target.id, source))


def get_scan(session: Session, scan_id: UUID) -> ScanDetail:
    job = session.get(ScanJob, scan_id)
    if job is None:
        raise ScanNotFoundError(scan_id)
    return scan_detail(job)


def synthetic_workload_response(job: SyntheticWorkloadJob) -> SyntheticWorkloadResponse:
    return SyntheticWorkloadResponse(
        job_id=job.id,
        target_id=job.target_id,
        status=JobStatus(job.status),
        query_count=job.query_count,
        rounds=job.rounds,
        fresh=job.fresh,
        generated=job.generated,
        succeeded=job.succeeded,
        failed=job.failed,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error=job.error,
    )


def start_synthetic_workload(
    session: Session,
    config: ProjectConfig,
    request: SyntheticWorkloadRequest,
) -> SyntheticWorkloadResponse:
    target = require_target(config, request.target_id)
    if not target.enabled:
        raise TargetDisabledError(target.id)
    if not target.synthetic_workload_enabled:
        raise SyntheticWorkloadDisabledError(target.id)
    try:
        target.workload_dsn()
    except ValueError as exc:
        raise WorkloadConfigurationError(str(exc)) from None
    return synthetic_workload_response(enqueue_workload(session, request))


def list_synthetic_workloads(
    session: Session,
    config: ProjectConfig,
    *,
    target_id: str | None = None,
    status: JobStatus | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> SyntheticWorkloadPage:
    query = select(SyntheticWorkloadJob)
    if target_id is not None:
        require_target(config, target_id)
        query = query.where(SyntheticWorkloadJob.target_id == target_id)
    if status is not None:
        query = query.where(SyntheticWorkloadJob.status == status)
    if since is not None:
        query = query.where(SyntheticWorkloadJob.created_at >= since)
    if until is not None:
        query = query.where(SyntheticWorkloadJob.created_at <= until)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    jobs = session.scalars(
        query.order_by(SyntheticWorkloadJob.created_at.desc(), SyntheticWorkloadJob.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return SyntheticWorkloadPage(
        items=[synthetic_workload_response(job) for job in jobs],
        total=total,
        limit=limit,
        offset=offset,
    )


def get_synthetic_workload(session: Session, job_id: UUID) -> SyntheticWorkloadResponse:
    job = session.get(SyntheticWorkloadJob, job_id)
    if job is None:
        raise SyntheticWorkloadNotFoundError(job_id)
    return synthetic_workload_response(job)


def finding_summary(finding: Finding) -> FindingSummary:
    return FindingSummary.model_validate(finding, from_attributes=True).model_copy(
        update={
            "query_sources": [
                QuerySource.model_validate(item)
                for item in finding.current_evidence.get("query_sources", [])
            ]
        }
    )


def list_findings(
    session: Session,
    config: ProjectConfig,
    *,
    target_id: str | None = None,
    scan_id: UUID | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> FindingPage:
    query = select(Finding)
    if scan_id is not None:
        if session.get(ScanJob, scan_id) is None:
            raise ScanNotFoundError(scan_id)
        query = query.where(Finding.observations.any(scan_id=scan_id))
    if target_id is not None:
        require_target(config, target_id)
        query = query.where(Finding.target_id == target_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if status is not None:
        query = query.where(Finding.status == status)
    if since is not None:
        query = query.where(Finding.last_seen >= since)
    if until is not None:
        query = query.where(Finding.last_seen <= until)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    findings = session.scalars(
        query.order_by(Finding.last_seen.desc(), Finding.id.desc()).limit(limit).offset(offset)
    ).all()
    return FindingPage(
        items=[finding_summary(item) for item in findings],
        total=total,
        limit=limit,
        offset=offset,
    )


def get_finding(session: Session, finding_id: UUID) -> FindingDetail:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)
    latest = session.scalar(
        select(Investigation)
        .where(Investigation.finding_id == finding.id)
        .order_by(Investigation.created_at.desc())
        .limit(1)
    )
    result = InvestigationResult.model_validate(latest.result) if latest and latest.result else None
    summary = finding_summary(finding)
    return FindingDetail(
        **summary.model_dump(),
        current_evidence=finding.current_evidence,
        observations=len(finding.observations),
        latest_investigation=result,
        investigation_status=InvestigationStatus(latest.status) if latest else None,
        investigation_error=latest.error if latest else None,
        investigation_model=latest.model_name if latest else None,
        investigation_created_at=latest.created_at if latest else None,
        investigation_input_tokens=latest.input_tokens if latest else None,
        investigation_output_tokens=latest.output_tokens if latest else None,
    )
