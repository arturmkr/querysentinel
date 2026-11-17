from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from querysentinel.config import DetectionConfig
from querysentinel.detector import Anomaly
from querysentinel.models import Finding, FindingObservation, ScanJob, utcnow
from querysentinel.schemas import FindingStatus


@dataclass(frozen=True)
class FindingEvent:
    finding: Finding
    event: str


def apply_findings(
    session: Session,
    job: ScanJob,
    anomalies: list[Anomaly],
    config: DetectionConfig,
    *,
    now: datetime | None = None,
) -> list[FindingEvent]:
    now = now or utcnow()
    cutoff = now - timedelta(minutes=config.max_age_minutes)
    events: list[FindingEvent] = []
    for anomaly in anomalies:
        observed_at = anomaly.observed_at or now
        stale = observed_at <= cutoff
        finding = session.scalar(
            select(Finding)
            .where(
                Finding.target_id == job.target_id,
                Finding.query_fingerprint == anomaly.fingerprint,
                Finding.anomaly_type == anomaly.anomaly_type,
            )
            .with_for_update()
        )
        event: str | None = None
        if finding is None:
            finding = Finding(
                target_id=job.target_id,
                query_fingerprint=anomaly.fingerprint,
                query_text=anomaly.query_text,
                anomaly_type=anomaly.anomaly_type,
                severity=anomaly.severity,
                status=FindingStatus.RESOLVED if stale else FindingStatus.OPEN,
                resolved_at=now if stale else None,
                resolution_reason="max_age" if stale else None,
                summary=anomaly.summary,
                current_evidence=anomaly.evidence,
                first_seen=observed_at,
                last_seen=observed_at,
            )
            session.add(finding)
            session.flush()
            if not stale:
                event = "new"
        else:
            last_seen = finding.last_seen
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=UTC)
            if observed_at < last_seen or (
                anomaly.observed_at is not None and observed_at == last_seen
            ):
                continue
            old_severity = finding.severity
            old_status = finding.status
            finding.last_seen = observed_at
            finding.query_text = anomaly.query_text
            finding.summary = anomaly.summary
            finding.current_evidence = anomaly.evidence
            finding.severity = anomaly.severity
            if old_status == FindingStatus.RESOLVED and not stale:
                finding.status = FindingStatus.OPEN
                finding.resolved_at = None
                finding.resolution_reason = None
                event = "reopened"
            elif old_severity != anomaly.severity and not stale:
                event = "severity_changed"
        session.add(
            FindingObservation(
                finding_id=finding.id,
                scan_id=job.id,
                observed_at=observed_at,
                severity=anomaly.severity,
                evidence=anomaly.evidence,
            )
        )
        if event:
            events.append(FindingEvent(finding, event))

    session.flush()
    expired = session.scalars(
        select(Finding)
        .where(
            Finding.target_id == job.target_id,
            Finding.status == FindingStatus.OPEN,
            Finding.last_seen <= cutoff,
        )
        .with_for_update()
    ).all()
    for finding in expired:
        finding.status = FindingStatus.RESOLVED
        finding.resolved_at = now
        finding.resolution_reason = "max_age"
        events.append(FindingEvent(finding, "resolved"))
    session.flush()
    return events
