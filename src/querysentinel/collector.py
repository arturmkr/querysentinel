from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from querysentinel.adapter import DatabaseAdapter, QueryCounter
from querysentinel.models import QueryCounterSnapshot, QueryIntervalMetric, ScanJob, utcnow

COUNTER_FIELDS = (
    "calls",
    "total_exec_time_ms",
    "rows",
    "shared_blks_hit",
    "shared_blks_read",
    "temp_blks_read",
    "temp_blks_written",
)


@dataclass(frozen=True)
class DeltaResult:
    compatible: bool
    reason: str | None
    values: dict[str, int | float]


def calculate_delta(current: QueryCounter, previous: QueryCounterSnapshot | None) -> DeltaResult:
    if previous is None:
        return DeltaResult(False, "first_observation", {})
    previous_reset = previous.stats_reset
    if previous_reset is not None and previous_reset.tzinfo is None:
        previous_reset = previous_reset.replace(tzinfo=UTC)
    if current.stats_reset != previous_reset:
        return DeltaResult(False, "statistics_reset", {})
    if (
        current.dealloc is not None
        and previous.dealloc is not None
        and current.dealloc < previous.dealloc
    ):
        return DeltaResult(False, "statistics_reset", {})
    values = {field: getattr(current, field) - getattr(previous, field) for field in COUNTER_FIELDS}
    if any(value < 0 for value in values.values()):
        return DeltaResult(False, "counter_decrease", {})
    if values["calls"] <= 0:
        return DeltaResult(False, "zero_calls", values)
    return DeltaResult(True, None, values)


def collect_scan(
    session: Session, job: ScanJob, adapter: DatabaseAdapter, min_calls: int = 10
) -> list[QueryIntervalMetric]:
    counters = adapter.collect_query_counters()
    intervals: list[QueryIntervalMetric] = []
    for counter in counters:
        previous = session.scalar(
            select(QueryCounterSnapshot)
            .where(
                QueryCounterSnapshot.target_id == job.target_id,
                QueryCounterSnapshot.fingerprint == counter.fingerprint,
            )
            .order_by(QueryCounterSnapshot.collected_at.desc())
            .limit(1)
        )
        snapshot = QueryCounterSnapshot(
            scan_id=job.id,
            target_id=job.target_id,
            dbid=counter.dbid,
            userid=counter.userid,
            queryid=counter.queryid,
            toplevel=counter.toplevel,
            fingerprint=counter.fingerprint,
            query_text=counter.query_text,
            calls=counter.calls,
            total_exec_time_ms=counter.total_exec_time_ms,
            rows=counter.rows,
            shared_blks_hit=counter.shared_blks_hit,
            shared_blks_read=counter.shared_blks_read,
            temp_blks_read=counter.temp_blks_read,
            temp_blks_written=counter.temp_blks_written,
            stats_reset=counter.stats_reset,
            dealloc=counter.dealloc,
            collected_at=utcnow(),
        )
        session.add(snapshot)
        snapshot.counter_epoch_start = previous.counter_epoch_start if previous else None
        if previous is None:
            values = {field: getattr(counter, field) for field in COUNTER_FIELDS}
            # The reset time bounds the cumulative stats when PostgreSQL supplies it.
            start = counter.stats_reset or snapshot.collected_at
            scope = "cumulative"
            snapshot.counter_epoch_start = snapshot.collected_at
        else:
            delta = calculate_delta(counter, previous)
            if delta.reason == "zero_calls":
                snapshot.pending_sample = previous.pending_sample
                continue
            if not delta.compatible:
                snapshot.counter_epoch_start = snapshot.collected_at
                continue
            values = delta.values
            start = previous.collected_at
            scope = "interval"
            if pending := previous.pending_sample:
                values = {
                    field: values[field] + pending["values"][field] for field in COUNTER_FIELDS
                }
                start = datetime.fromisoformat(pending["start"])
                scope = pending["scope"]

        calls = int(values["calls"])
        if calls < min_calls:
            if calls:
                snapshot.pending_sample = {
                    "values": values,
                    "start": start.isoformat(),
                    "scope": scope,
                }
            continue
        total_time = float(values["total_exec_time_ms"])
        interval = QueryIntervalMetric(
            scan_id=job.id,
            target_id=job.target_id,
            fingerprint=counter.fingerprint,
            query_text=counter.query_text,
            interval_start=start,
            interval_end=snapshot.collected_at,
            calls=calls,
            total_exec_time_ms=total_time,
            mean_exec_time_ms=total_time / calls,
            rows=int(values["rows"]),
            shared_blks_hit=int(values["shared_blks_hit"]),
            shared_blks_read=int(values["shared_blks_read"]),
            temp_blks_read=int(values["temp_blks_read"]),
            temp_blks_written=int(values["temp_blks_written"]),
            compatible=True,
            sample_scope=scope,
            username=counter.username,
            counter_epoch_start=snapshot.counter_epoch_start,
        )
        session.add(interval)
        intervals.append(interval)
    session.flush()
    return intervals
