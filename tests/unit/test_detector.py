from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from querysentinel.config import DetectionConfig
from querysentinel.detector import detect_anomalies
from querysentinel.models import QueryIntervalMetric
from querysentinel.schemas import AnomalyType


def metric(scan_id, end, mean, calls=20, total=None):
    return QueryIntervalMetric(
        scan_id=scan_id,
        target_id="airlines",
        fingerprint="f" * 64,
        query_text="SELECT * FROM bookings.flights",
        interval_start=end - timedelta(minutes=5),
        interval_end=end,
        calls=calls,
        total_exec_time_ms=total if total is not None else mean * calls,
        mean_exec_time_ms=mean,
        rows=calls,
        shared_blks_hit=1000,
        shared_blks_read=0,
        temp_blks_read=0,
        temp_blks_written=0,
        compatible=True,
    )


def test_new_expensive_requires_real_interval_and_samples(session) -> None:
    current = metric(uuid4(), datetime.now(UTC), 300)
    session.add(current)
    session.flush()
    anomalies = detect_anomalies(session, [current], DetectionConfig())
    assert [item.anomaly_type for item in anomalies] == [AnomalyType.NEW_EXPENSIVE]
    low_sample = metric(uuid4(), datetime.now(UTC), 500, calls=2)
    assert detect_anomalies(session, [low_sample], DetectionConfig()) == []


def test_latency_and_workload_regression_compare_successive_intervals(session) -> None:
    now = datetime.now(UTC)
    before = metric(uuid4(), now - timedelta(minutes=5), 25, total=500)
    session.add(before)
    session.commit()
    after = metric(uuid4(), now, 100, total=2200)
    anomalies = detect_anomalies(session, [after], DetectionConfig())
    kinds = {item.anomaly_type for item in anomalies}
    assert AnomalyType.LATENCY_REGRESSION in kinds
    assert AnomalyType.WORKLOAD_REGRESSION in kinds
