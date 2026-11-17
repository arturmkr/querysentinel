from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from querysentinel.config import DetectionConfig, TargetConfig
from querysentinel.error_logs import collect_postgresql_logs
from querysentinel.findings import apply_findings
from querysentinel.models import Finding, FindingObservation, ScanJob
from querysentinel.schemas import FindingStatus


def test_insert_error_refreshes_max_age_and_reopens_without_replaying_logs(session, tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    config = DetectionConfig(max_age_minutes=5)
    target = TargetConfig(
        id="lego",
        engine="postgresql",
        dsn_env="UNUSED",
        error_log_dir=tmp_path,
        error_log_database="lego",
    )

    def append_error(minute, *, database="lego", file="postgresql-1.json", client="orders-import"):
        observed = start + timedelta(minutes=minute)
        with (tmp_path / file).open("a") as log:
            log.write(
                json.dumps(
                    {
                        "timestamp": observed.strftime("%Y-%m-%d %H:%M:%S.000 UTC"),
                        "dbname": database,
                        "backend_type": "client backend",
                        "error_severity": "ERROR",
                        "state_code": "22P02",
                        "user": "orders",
                        "application_name": client,
                        "ps": "INSERT",
                        "message": "private-value",
                    }
                )
                + "\n"
            )

    def scan(minute):
        now = start + timedelta(minutes=minute)
        job = ScanJob(target_id=target.id)
        session.add(job)
        session.flush()
        errors = collect_postgresql_logs(session, target)
        events = apply_findings(session, job, errors, config, now=now)
        session.commit()
        return [event.event for event in events]

    append_error(0, database="airlines")
    append_error(0)
    append_error(1)
    append_error(1, client="PyCharm")
    assert scan(2) == ["new"]
    finding = session.query(Finding).one()
    finding_id = finding.id
    assert finding.current_evidence["occurrences_in_scan"] == 3
    assert [
        (source["username"], source["client"], source["occurrences"])
        for source in finding.current_evidence["query_sources"]
    ] == [("orders", "orders-import", 2), ("orders", "PyCharm", 1)]
    assert "private-value" not in finding.summary
    assert scan(3) == []
    assert session.query(FindingObservation).count() == 1
    append_error(4, file="postgresql-2.json")
    assert scan(5) == []
    assert scan(8) == []
    assert scan(9) == ["resolved"]
    assert finding.status == FindingStatus.RESOLVED
    append_error(10, file="postgresql-2.json")
    assert scan(11) == ["reopened"]
    assert session.query(Finding).one().id == finding_id
