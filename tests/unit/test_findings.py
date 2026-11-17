from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from querysentinel.config import DetectionConfig
from querysentinel.detector import Anomaly
from querysentinel.findings import apply_findings
from querysentinel.models import Finding, ScanJob
from querysentinel.schemas import AnomalyType, FindingStatus, JobSource, Severity


def anomaly(severity=Severity.HIGH):
    return Anomaly(
        fingerprint="f" * 64,
        query_text="SELECT 1",
        anomaly_type=AnomalyType.LATENCY_REGRESSION,
        severity=severity,
        summary="regressed",
        evidence={"ratio": 4.0},
    )


def job():
    return ScanJob(target_id="airlines", source=JobSource.MANUAL)


def test_finding_deduplicates_and_notifies_only_changes(session) -> None:
    first = job()
    session.add(first)
    session.flush()
    events = apply_findings(session, first, [anomaly()], DetectionConfig())
    session.commit()
    assert [event.event for event in events] == ["new"]
    assert session.query(Finding).one().query_text == "SELECT 1"

    second = job()
    session.add(second)
    session.flush()
    events = apply_findings(session, second, [anomaly()], DetectionConfig())
    session.commit()
    assert events == []
    assert session.query(Finding).count() == 1


def test_max_age_expires_after_last_observation_and_reopens_same_id(session) -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    config = DetectionConfig(max_age_minutes=5)

    def scan(minutes, anomalies=(), target_id="airlines"):
        current_job = ScanJob(target_id=target_id)
        session.add(current_job)
        session.flush()
        events = apply_findings(
            session, current_job, list(anomalies), config, now=start + timedelta(minutes=minutes)
        )
        session.commit()
        return events

    [opened] = scan(0, [anomaly()])
    finding_id = opened.finding.id
    assert scan(4, [anomaly()]) == []
    assert scan(5) == []
    assert scan(9, target_id="other") == []
    assert opened.finding.status == FindingStatus.OPEN
    [closed] = scan(9)
    assert closed.event == "resolved"
    assert closed.finding.status == FindingStatus.RESOLVED
    assert closed.finding.resolution_reason == "max_age"
    assert closed.finding.last_seen.replace(tzinfo=UTC) == start + timedelta(minutes=4)
    assert closed.finding.resolved_at.replace(tzinfo=UTC) == start + timedelta(minutes=9)
    assert scan(10) == []
    [reopened] = scan(11, [anomaly()])
    assert reopened.event == "reopened"
    assert reopened.finding.id == finding_id
    assert reopened.finding.resolution_reason is None
    assert reopened.finding.resolved_at is None


def test_first_seen_after_max_age_keeps_history_without_opening_an_alert(session) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    current_job = job()
    session.add(current_job)
    session.flush()
    old_error = replace(
        anomaly(),
        anomaly_type=AnomalyType.EXECUTION_ERROR,
        observed_at=now - timedelta(minutes=10),
    )
    assert (
        apply_findings(
            session, current_job, [old_error], DetectionConfig(max_age_minutes=5), now=now
        )
        == []
    )
    finding = session.query(Finding).one()
    assert finding.status == FindingStatus.RESOLVED
    assert finding.resolution_reason == "max_age"
