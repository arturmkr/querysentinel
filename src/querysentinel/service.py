from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from querysentinel.adapter import PostgreSQLAdapter
from querysentinel.collector import collect_scan
from querysentinel.config import ProjectConfig, Settings, TargetConfig
from querysentinel.detector import detect_anomalies
from querysentinel.error_logs import attribute_slow_queries, collect_postgresql_logs
from querysentinel.findings import apply_findings
from querysentinel.investigator import investigate
from querysentinel.jobs import complete_job, heartbeat
from querysentinel.models import (
    Finding,
    Investigation,
    QueryCounterSnapshot,
    QueryIntervalMetric,
    ScanJob,
    SlowQueryObservation,
)
from querysentinel.notifier import ConsoleNotifier, WebhookNotifier, deliver_notification
from querysentinel.schemas import InvestigationStatus

logger = structlog.get_logger()
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _safe_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: investigation unavailable"[:2000]


def run_scan(
    session: Session,
    job: ScanJob,
    target: TargetConfig,
    project: ProjectConfig,
    settings: Settings,
) -> None:
    adapter = PostgreSQLAdapter(
        target.id,
        target.dsn(),
        settings.statement_timeout_ms,
        settings.lock_timeout_ms,
    )
    metrics = collect_scan(session, job, adapter, project.detection.min_calls_per_interval)
    anomalies = detect_anomalies(session, metrics, project.detection)
    now = datetime.now(UTC)
    errors = collect_postgresql_logs(
        session, target, slow_query_cutoff=now - timedelta(days=project.retention.interval_days)
    )
    if target.error_log_dir is not None:
        anomalies = attribute_slow_queries(session, metrics, anomalies)
    events = apply_findings(session, job, [*anomalies, *errors], project.detection, now=now)
    session.commit()

    ranked = sorted(
        anomalies,
        key=lambda anomaly: SEVERITY_ORDER[anomaly.severity.value],
        reverse=True,
    )
    limit = project.detection.max_llm_investigations_per_scan
    for position, anomaly in enumerate(ranked):
        heartbeat(session, job.id, settings.job_lease_seconds)
        finding = session.scalar(
            select(Finding).where(
                Finding.target_id == job.target_id,
                Finding.query_fingerprint == anomaly.fingerprint,
                Finding.anomaly_type == anomaly.anomaly_type,
            )
        )
        if finding is None:
            continue
        investigation = Investigation(
            finding_id=finding.id,
            scan_id=job.id,
            status=InvestigationStatus.FAILED_OR_SKIPPED,
            model_name=settings.ai_model if settings.model_credentials_configured() else None,
        )
        session.add(investigation)
        if position >= limit:
            investigation.error = "per-scan investigation limit reached"
        elif not settings.model_credentials_configured():
            provider = settings.ai_model.partition(":")[0]
            investigation.error = (
                f"credentials for AI provider {provider!r} are not configured; "
                "deterministic finding retained"
            )
        else:
            try:
                result, input_tokens, output_tokens = investigate(settings, adapter, job, anomaly)
                if (
                    result.target_id != job.target_id
                    or result.scan_id != job.id
                    or result.query_fingerprint != anomaly.fingerprint
                    or result.anomaly_type != anomaly.anomaly_type
                ):
                    raise ValueError("investigation identity did not match deterministic finding")
            except Exception as exc:
                investigation.error = _safe_error(exc)
                logger.warning(
                    "investigation_failed",
                    target_id=job.target_id,
                    scan_id=str(job.id),
                    error_type=type(exc).__name__,
                )
            else:
                investigation.status = result.status
                investigation.result = result.model_dump(mode="json")
                investigation.input_tokens = input_tokens
                investigation.output_tokens = output_tokens
        session.commit()

    notifiers = []
    if project.notifications.console:
        notifiers.append(ConsoleNotifier())
    if project.notifications.webhook and settings.webhook_url:
        notifiers.append(WebhookNotifier(settings.webhook_url))
    for event in events:
        for notifier in notifiers:
            deliver_notification(session, job, event.finding, event.event, notifier)

    _apply_retention(session, project, job.target_id)
    complete_job(session, job)


def _apply_retention(session: Session, project: ProjectConfig, target_id: str) -> None:
    now = datetime.now(UTC)
    interval_cutoff = now - timedelta(days=project.retention.interval_days)
    session.execute(
        delete(QueryIntervalMetric).where(
            QueryIntervalMetric.target_id == target_id,
            QueryIntervalMetric.interval_end < interval_cutoff,
        )
    )
    session.execute(
        delete(SlowQueryObservation).where(
            SlowQueryObservation.target_id == target_id,
            SlowQueryObservation.observed_at < interval_cutoff,
        )
    )
    session.execute(
        delete(QueryCounterSnapshot).where(
            QueryCounterSnapshot.target_id == target_id,
            QueryCounterSnapshot.collected_at
            < now - timedelta(days=project.retention.checkpoint_days),
        )
    )
    session.commit()
