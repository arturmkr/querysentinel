from __future__ import annotations

import signal
import time
from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from querysentinel.config import get_settings, load_project_config
from querysentinel.db import get_session_factory
from querysentinel.jobs import ActiveScanError, claim_job, enqueue_job, fail_job
from querysentinel.logging import configure_logging
from querysentinel.schemas import JobSource
from querysentinel.service import run_scan
from querysentinel.synthetic_workload import run_synthetic_workload
from querysentinel.workload_jobs import (
    claim_workload,
    complete_workload,
    fail_workload,
)

logger = structlog.get_logger()
stopping = False


def _stop(*_args) -> None:
    global stopping
    stopping = True


def _enqueue_scheduled(target_id: str) -> None:
    window = datetime.now(UTC).replace(second=0, microsecond=0)
    with get_session_factory()() as session:
        try:
            enqueue_job(session, target_id, JobSource.SCHEDULED, window)
        except ActiveScanError as exc:
            logger.info(
                "scheduled_scan_skipped_active",
                target_id=target_id,
                scan_id=str(exc.job.id),
            )


def main() -> None:
    settings = get_settings()
    project = load_project_config()
    configure_logging(settings.log_level)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    scheduler = BackgroundScheduler(timezone="UTC")
    for target in project.targets:
        if not target.enabled:
            continue
        scheduler.add_job(
            _enqueue_scheduled,
            CronTrigger.from_crontab(target.schedule or project.schedule.cron, timezone="UTC"),
            args=[target.id],
            id=f"scan-{target.id}",
            coalesce=True,
            max_instances=1,
        )
    scheduler.start()
    logger.info(
        "worker_started", targets=[target.id for target in project.targets if target.enabled]
    )
    try:
        while not stopping:
            with get_session_factory()() as session:
                job = claim_job(
                    session,
                    lease_seconds=settings.job_lease_seconds,
                    max_attempts=settings.job_max_attempts,
                )
                if job is None:
                    workload_job = claim_workload(session)
                    if workload_job is None:
                        time.sleep(1)
                        continue
                    target = project.target(workload_job.target_id)
                    if target is None or not target.synthetic_workload_enabled:
                        fail_workload(session, workload_job, "target missing or workload disabled")
                        continue
                    try:
                        result = run_synthetic_workload(
                            dsn=target.workload_dsn(),
                            model=settings.ai_model,
                            target_id=target.id,
                            query_count=workload_job.query_count,
                            rounds=workload_job.rounds,
                            fresh=workload_job.fresh,
                            cache_dir=settings.synthetic_workload_cache_dir,
                        )
                    except Exception as exc:
                        session.rollback()
                        logger.exception(
                            "synthetic_workload_failed",
                            target_id=workload_job.target_id,
                            workload_job_id=str(workload_job.id),
                            error_type=type(exc).__name__,
                        )
                        fail_workload(
                            session,
                            workload_job,
                            f"{type(exc).__name__}: {str(exc)[:1000]}",
                        )
                    else:
                        complete_workload(
                            session,
                            workload_job,
                            generated=result.generated,
                            succeeded=result.succeeded,
                            failed=result.failed,
                        )
                    continue
                target = project.target(job.target_id)
                if target is None or not target.enabled:
                    fail_job(session, job, "target missing or disabled", 1)
                    continue
                try:
                    run_scan(session, job, target, project, settings)
                except Exception as exc:
                    session.rollback()
                    logger.exception(
                        "scan_failed",
                        target_id=job.target_id,
                        scan_id=str(job.id),
                        error_type=type(exc).__name__,
                    )
                    fail_job(
                        session,
                        job,
                        f"{type(exc).__name__}: scan failed",
                        settings.job_max_attempts,
                    )
    finally:
        scheduler.shutdown(wait=False)
        logger.info("worker_stopped")


if __name__ == "__main__":
    main()
