from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from querysentinel.adapter import QueryCounter
from querysentinel.collector import calculate_delta, collect_scan
from querysentinel.config import DetectionConfig
from querysentinel.detector import detect_anomalies
from querysentinel.models import QueryCounterSnapshot, ScanJob
from querysentinel.schemas import AnomalyType

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def counter(**overrides) -> QueryCounter:
    values = {
        "target_id": "airlines",
        "dbid": 1,
        "userid": 2,
        "queryid": 3,
        "toplevel": True,
        "query_text": "SELECT 1",
        "calls": 20,
        "total_exec_time_ms": 200.0,
        "rows": 20,
        "shared_blks_hit": 100,
        "shared_blks_read": 10,
        "temp_blks_read": 0,
        "temp_blks_written": 0,
        "stats_reset": NOW,
        "dealloc": 0,
    }
    values.update(overrides)
    return QueryCounter(**values)


def snapshot(**overrides) -> QueryCounterSnapshot:
    values = {
        "scan_id": uuid4(),
        "target_id": "airlines",
        "dbid": 1,
        "userid": 2,
        "queryid": 3,
        "toplevel": True,
        "fingerprint": "a" * 64,
        "query_text": "SELECT 1",
        "calls": 10,
        "total_exec_time_ms": 50.0,
        "rows": 10,
        "shared_blks_hit": 50,
        "shared_blks_read": 5,
        "temp_blks_read": 0,
        "temp_blks_written": 0,
        "stats_reset": NOW,
        "dealloc": 0,
        "collected_at": NOW,
    }
    values.update(overrides)
    return QueryCounterSnapshot(**values)


def test_first_observation_has_no_interval() -> None:
    result = calculate_delta(counter(), None)
    assert not result.compatible
    assert result.reason == "first_observation"


def test_delta_uses_counter_differences() -> None:
    result = calculate_delta(counter(), snapshot())
    assert result.compatible
    assert result.values["calls"] == 10
    assert result.values["total_exec_time_ms"] == 150.0


def test_reset_and_counter_decrease_are_incompatible() -> None:
    reset = calculate_delta(counter(stats_reset=datetime(2026, 1, 2, tzinfo=UTC)), snapshot())
    decrease = calculate_delta(counter(calls=5), snapshot())
    assert reset.reason == "statistics_reset"
    assert decrease.reason == "counter_decrease"


def test_zero_calls_does_not_fabricate_mean() -> None:
    result = calculate_delta(counter(calls=10, total_exec_time_ms=50), snapshot())
    assert not result.compatible
    assert result.reason == "zero_calls"


@pytest.mark.parametrize("counts", [(10,), (5, 5, 10)])
def test_expensive_query_is_detected_as_soon_as_ten_calls_accumulate(session, counts) -> None:
    def scan(calls):
        job = ScanJob(target_id="airlines")
        session.add(job)
        session.flush()
        adapter = SimpleNamespace(
            collect_query_counters=lambda: [
                counter(calls=calls, total_exec_time_ms=calls * 300, rows=calls)
            ]
        )
        metrics = collect_scan(session, job, adapter, min_calls=10)
        session.commit()
        return metrics

    for calls in counts[:-1]:
        assert scan(calls) == []
    metrics = scan(counts[-1])
    assert len(metrics) == 1
    assert metrics[0].calls == 10
    anomalies = detect_anomalies(session, metrics, DetectionConfig())
    assert [item.anomaly_type for item in anomalies] == [AnomalyType.NEW_EXPENSIVE]
    assert anomalies[0].evidence["sample_scope"] == "cumulative"
    assert scan(10) == []
    assert scan(15) == []
    [interval] = scan(20)
    assert interval.calls == 10
    assert interval.sample_scope == "interval"
    assert interval.mean_exec_time_ms == 300


def test_reset_discards_pending_calls(session) -> None:
    def scan(calls, reset):
        job = ScanJob(target_id="airlines")
        session.add(job)
        session.flush()
        adapter = SimpleNamespace(
            collect_query_counters=lambda: [
                counter(calls=calls, total_exec_time_ms=calls * 300, rows=calls, stats_reset=reset)
            ]
        )
        metrics = collect_scan(session, job, adapter, min_calls=10)
        session.commit()
        return metrics

    new_epoch = datetime(2026, 1, 2, tzinfo=UTC)
    assert scan(5, NOW) == []
    assert scan(1, new_epoch) == []
    assert scan(6, new_epoch) == []
    [interval] = scan(11, new_epoch)
    assert interval.calls == 10
    assert interval.sample_scope == "interval"
