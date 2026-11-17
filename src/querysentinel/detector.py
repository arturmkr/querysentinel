from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from querysentinel.config import DetectionConfig
from querysentinel.models import QueryIntervalMetric
from querysentinel.schemas import AnomalyType, QuerySource, Severity


@dataclass(frozen=True)
class Anomaly:
    fingerprint: str
    query_text: str
    anomaly_type: AnomalyType
    severity: Severity
    summary: str
    evidence: dict[str, Any]
    observed_at: datetime | None = None


def _severity(ratio: float) -> Severity:
    if ratio >= 10:
        return Severity.CRITICAL
    if ratio >= 5:
        return Severity.HIGH
    if ratio >= 3:
        return Severity.MEDIUM
    return Severity.LOW


def _previous_interval(
    session: Session, metric: QueryIntervalMetric, min_calls: int
) -> QueryIntervalMetric | None:
    query = select(QueryIntervalMetric).where(
        QueryIntervalMetric.target_id == metric.target_id,
        QueryIntervalMetric.fingerprint == metric.fingerprint,
        QueryIntervalMetric.scan_id != metric.scan_id,
        QueryIntervalMetric.compatible.is_(True),
        QueryIntervalMetric.sample_scope == "interval",
        QueryIntervalMetric.calls >= min_calls,
        QueryIntervalMetric.interval_end <= metric.interval_start,
    )
    if metric.counter_epoch_start is not None:
        query = query.where(QueryIntervalMetric.interval_start >= metric.counter_epoch_start)
    return session.scalar(query.order_by(QueryIntervalMetric.interval_end.desc()).limit(1))


def detect_anomalies(
    session: Session, metrics: list[QueryIntervalMetric], config: DetectionConfig
) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for metric in metrics:
        if metric.calls < config.min_calls_per_interval:
            continue
        cumulative = metric.sample_scope == "cumulative"
        previous = (
            None
            if cumulative
            else _previous_interval(session, metric, config.min_calls_per_interval)
        )
        common = {
            "calls": metric.calls,
            "sample_scope": "cumulative" if cumulative else "interval",
            "mean_exec_time_ms": metric.mean_exec_time_ms,
            "total_exec_time_ms": metric.total_exec_time_ms,
            "shared_blks_read": metric.shared_blks_read,
            "shared_blks_hit": metric.shared_blks_hit,
            "temp_blks_read": metric.temp_blks_read,
            "temp_blks_written": metric.temp_blks_written,
        }
        if metric.username:
            common["query_sources"] = [
                QuerySource(
                    username=metric.username,
                    last_seen=metric.interval_end,
                    occurrences=metric.calls,
                ).model_dump(mode="json")
            ]
        if metric.mean_exec_time_ms >= config.expensive_query_mean_ms:
            ratio = metric.mean_exec_time_ms / config.expensive_query_mean_ms
            anomalies.append(
                Anomaly(
                    metric.fingerprint,
                    metric.query_text,
                    AnomalyType.NEW_EXPENSIVE,
                    _severity(max(ratio, 3)),
                    (f"Query averaged {metric.mean_exec_time_ms:.1f} ms over {metric.calls} calls"),
                    common,
                )
            )
        if cumulative:
            continue
        if previous is not None:
            latency_ratio = metric.mean_exec_time_ms / max(previous.mean_exec_time_ms, 0.001)
            if (
                metric.mean_exec_time_ms >= config.meaningful_latency_ms
                and latency_ratio >= config.latency_regression_factor
            ):
                anomalies.append(
                    Anomaly(
                        metric.fingerprint,
                        metric.query_text,
                        AnomalyType.LATENCY_REGRESSION,
                        _severity(latency_ratio),
                        f"Mean latency regressed {latency_ratio:.1f}x",
                        common
                        | {
                            "before_mean_exec_time_ms": previous.mean_exec_time_ms,
                            "after_mean_exec_time_ms": metric.mean_exec_time_ms,
                            "ratio": latency_ratio,
                        },
                    )
                )
            workload_ratio = metric.total_exec_time_ms / max(previous.total_exec_time_ms, 0.001)
            if (
                metric.total_exec_time_ms >= config.meaningful_latency_ms * metric.calls
                and workload_ratio >= config.workload_regression_factor
            ):
                anomalies.append(
                    Anomaly(
                        metric.fingerprint,
                        metric.query_text,
                        AnomalyType.WORKLOAD_REGRESSION,
                        _severity(workload_ratio),
                        f"Interval workload cost regressed {workload_ratio:.1f}x",
                        common
                        | {
                            "before_total_exec_time_ms": previous.total_exec_time_ms,
                            "after_total_exec_time_ms": metric.total_exec_time_ms,
                            "ratio": workload_ratio,
                        },
                    )
                )
        temp_blocks = metric.temp_blks_read + metric.temp_blks_written
        if temp_blocks >= config.temp_blocks_threshold:
            anomalies.append(
                Anomaly(
                    metric.fingerprint,
                    metric.query_text,
                    AnomalyType.HIGH_TEMP_IO,
                    Severity.MEDIUM,
                    f"Query used {temp_blocks} temporary blocks",
                    common | {"temporary_blocks": temp_blocks},
                )
            )
        total_shared = metric.shared_blks_hit + metric.shared_blks_read
        read_ratio = metric.shared_blks_read / total_shared if total_shared else 0.0
        previous_read_ratio = 0.0
        if previous:
            previous_total = previous.shared_blks_hit + previous.shared_blks_read
            previous_read_ratio = (
                previous.shared_blks_read / previous_total if previous_total else 0.0
            )
        if (
            total_shared >= 100
            and read_ratio >= config.block_read_ratio_threshold
            and (previous is None or read_ratio >= previous_read_ratio * 2)
        ):
            anomalies.append(
                Anomaly(
                    metric.fingerprint,
                    metric.query_text,
                    AnomalyType.BLOCK_READ_REGRESSION,
                    Severity.MEDIUM,
                    f"Shared block read ratio reached {read_ratio:.1%}",
                    common | {"read_ratio": read_ratio, "before_read_ratio": previous_read_ratio},
                )
            )
    return anomalies
