"""Collect SQL errors and slow-execution sources from PostgreSQL JSON logs."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from dataclasses import replace
from datetime import datetime
from typing import Any

from psycopg import errors
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from querysentinel.config import TargetConfig
from querysentinel.detector import Anomaly
from querysentinel.models import (
    ErrorLogCheckpoint,
    QueryCounterSnapshot,
    QueryIntervalMetric,
    SlowQueryObservation,
)
from querysentinel.schemas import AnomalyType, QuerySource, Severity

SQL_OPERATIONS = {
    "ALTER",
    "BEGIN",
    "CALL",
    "COMMIT",
    "COPY",
    "CREATE",
    "DELETE",
    "DROP",
    "INSERT",
    "MERGE",
    "SELECT",
    "TRUNCATE",
    "UPDATE",
    "VACUUM",
}
DURATION_MESSAGE = re.compile(r"^duration: \d+(?:\.\d+)? ms\s+(?:statement:|execute\s)")


def _execution_error(record: dict[str, Any]) -> tuple[Anomaly, QuerySource] | None:
    state = record.get("state_code", "")
    if record.get("error_severity") != "ERROR" or not re.fullmatch(r"[0-9A-Z]{5}", state):
        return None
    observed_at = datetime.fromisoformat(record["timestamp"].replace(" UTC", "+00:00"))
    command = record.get("ps", "").upper().partition(" ")[0]
    operation = command if command in SQL_OPERATIONS else "SQL"
    query_id = record.get("query_id")
    # PostgreSQL may have no query ID for errors that occur before planning.
    identity = f"{state}:{query_id or operation}"
    try:
        name = errors.lookup(state).__name__
        error_name = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name).lower()
    except KeyError:
        error_name = "execution error"
    anomaly = Anomaly(
        fingerprint=hashlib.sha256(identity.encode()).hexdigest(),
        query_text="",
        anomaly_type=AnomalyType.EXECUTION_ERROR,
        severity=Severity.HIGH,
        summary=f"PostgreSQL {operation} failed: {error_name} ({state})",
        evidence={
            "source": "postgresql_jsonlog",
            "sqlstate": state,
            "operation": operation,
            "query_id": query_id or None,
            "occurrences_in_scan": 1,
        },
        observed_at=observed_at,
    )
    return anomaly, QuerySource(
        username=record.get("user") or None,
        client=record.get("application_name") or None,
        last_seen=observed_at,
        occurrences=1,
    )


def _slow_query_source(record: dict[str, Any], target_id: str) -> SlowQueryObservation | None:
    query_id = record.get("query_id")
    username = record.get("user")
    client = record.get("application_name")
    if (
        record.get("error_severity") != "LOG"
        or not isinstance(query_id, int)
        or not query_id
        or not username
        or not client
        or not DURATION_MESSAGE.match(record.get("message", ""))
    ):
        return None
    return SlowQueryObservation(
        target_id=target_id,
        query_id=query_id,
        username=username,
        client=client,
        observed_at=datetime.fromisoformat(record["timestamp"].replace(" UTC", "+00:00")),
    )


def collect_postgresql_logs(
    session: Session, target: TargetConfig, *, slow_query_cutoff: datetime | None = None
) -> list[Anomaly]:
    directory = target.error_log_dir
    database = target.error_log_database
    if directory is None or database is None:
        return []
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise RuntimeError("No PostgreSQL JSON logs found for configured error source")
    source = f"{directory.resolve()}:{database}"
    checkpoint = session.get(ErrorLogCheckpoint, target.id)
    previous = checkpoint.positions if checkpoint and checkpoint.source == source else {}
    positions: dict[str, list[int]] = {}
    findings: dict[str, Anomaly] = {}
    sources: dict[str, dict[tuple[str | None, str | None], QuerySource]] = defaultdict(dict)
    for path in paths:
        with path.open("rb") as handle:
            stat = os.fstat(handle.fileno())
            inode, offset = previous.get(path.name, (0, 0))
            if inode != stat.st_ino or offset > stat.st_size:
                offset = 0
            handle.seek(offset)
            # Bound a scan to the bytes present at open and retry an incomplete final line.
            while offset < stat.st_size:
                line = handle.readline(stat.st_size - offset)
                if not line.endswith(b"\n"):
                    break
                offset += len(line)
                record = json.loads(line)
                if (
                    record.get("dbname") != database
                    or record.get("backend_type") != "client backend"
                    or record.get("application_name") == "querysentinel_collector"
                ):
                    continue
                if slow_query := _slow_query_source(record, target.id):
                    if slow_query_cutoff is None or slow_query.observed_at >= slow_query_cutoff:
                        session.add(slow_query)
                    continue
                entry = _execution_error(record)
                if entry is None:
                    continue
                anomaly, attribution = entry
                key = (attribution.username, attribution.client)
                by_source = sources[anomaly.fingerprint]
                if source_entry := by_source.get(key):
                    source_entry.occurrences += 1
                    source_entry.last_seen = max(source_entry.last_seen, attribution.last_seen)
                else:
                    by_source[key] = attribution
                prior = findings.get(anomaly.fingerprint)
                if prior is None:
                    findings[anomaly.fingerprint] = anomaly
                    continue
                assert prior.observed_at is not None and anomaly.observed_at is not None
                latest = max((prior, anomaly), key=lambda finding: finding.observed_at)
                findings[anomaly.fingerprint] = replace(
                    latest,
                    evidence=latest.evidence
                    | {"occurrences_in_scan": prior.evidence["occurrences_in_scan"] + 1},
                )
            positions[path.name] = [stat.st_ino, offset]
    if checkpoint is None:
        checkpoint = ErrorLogCheckpoint(target_id=target.id)
        session.add(checkpoint)
    checkpoint.source = source
    checkpoint.positions = positions
    return [
        replace(
            finding,
            evidence=finding.evidence
            | {
                "query_sources": [
                    item.model_dump(mode="json")
                    for item in sorted(
                        sources[finding.fingerprint].values(),
                        key=lambda item: (item.occurrences, item.last_seen),
                        reverse=True,
                    )
                ]
            },
        )
        for finding in findings.values()
    ]


def attribute_slow_queries(
    session: Session, metrics: list[QueryIntervalMetric], anomalies: list[Anomaly]
) -> list[Anomaly]:
    if not anomalies or not metrics:
        return anomalies
    fingerprint_set = {anomaly.fingerprint for anomaly in anomalies}
    query_ids = dict(
        session.execute(
            select(QueryCounterSnapshot.fingerprint, QueryCounterSnapshot.queryid).where(
                QueryCounterSnapshot.scan_id == metrics[0].scan_id,
                QueryCounterSnapshot.fingerprint.in_(fingerprint_set),
                QueryCounterSnapshot.toplevel.is_(True),
            )
        )
        .tuples()
        .all()
    )
    sources = {}
    for metric in metrics:
        query_id = query_ids.get(metric.fingerprint)
        if not query_id or not metric.username:
            continue
        rows = session.execute(
            select(
                SlowQueryObservation.client,
                func.count().label("occurrences"),
                func.max(SlowQueryObservation.observed_at).label("last_seen"),
            )
            .where(
                SlowQueryObservation.target_id == metric.target_id,
                SlowQueryObservation.query_id == query_id,
                SlowQueryObservation.username == metric.username,
                SlowQueryObservation.observed_at > metric.interval_start,
                SlowQueryObservation.observed_at <= metric.interval_end,
            )
            .group_by(SlowQueryObservation.client)
            .order_by(func.count().desc(), SlowQueryObservation.client)
        )
        if clients := rows.all():
            sources[metric.fingerprint] = [
                QuerySource(
                    username=metric.username,
                    client=client,
                    last_seen=last_seen,
                    occurrences=occurrences,
                    observation_kind="duration_log",
                ).model_dump(mode="json")
                for client, occurrences, last_seen in clients
            ]
    return [
        replace(
            anomaly, evidence=anomaly.evidence | {"query_sources": sources[anomaly.fingerprint]}
        )
        if anomaly.fingerprint in sources
        else anomaly
        for anomaly in anomalies
    ]
