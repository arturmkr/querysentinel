from __future__ import annotations

import os
import time
from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import sessionmaker
from testcontainers.community.postgres import PostgresContainer

from alembic import command
from querysentinel.adapter import PostgreSQLAdapter
from querysentinel.api import app
from querysentinel.collector import collect_scan
from querysentinel.config import (
    DetectionConfig,
    ProjectConfig,
    Settings,
    TargetConfig,
    get_settings,
)
from querysentinel.db import session_dependency
from querysentinel.detector import detect_anomalies
from querysentinel.findings import apply_findings
from querysentinel.jobs import claim_job, enqueue_job
from querysentinel.models import Finding, FindingObservation, NotificationDelivery, ScanJob
from querysentinel.notifier import Notifier, deliver_notification
from querysentinel.schemas import AnomalyType, JobSource, JobStatus, Severity
from querysentinel.service import run_scan

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def state_database_url() -> Iterator[str]:
    with PostgresContainer(
        image="postgres:18",
        username="sentinel_test",
        password="sentinel_test_password",
        dbname="sentinel_test",
        driver="psycopg",
    ) as postgres:
        url = postgres.get_connection_url()
        previous = os.environ.get("SENTINEL_DATABASE_URL")
        os.environ["SENTINEL_DATABASE_URL"] = url
        get_settings.cache_clear()
        command.upgrade(Config("alembic.ini"), "head")
        yield url
        if previous is None:
            os.environ.pop("SENTINEL_DATABASE_URL", None)
        else:
            os.environ["SENTINEL_DATABASE_URL"] = previous
        get_settings.cache_clear()


@pytest.fixture(scope="session")
def target_database() -> Iterator[dict[str, str]]:
    container = PostgresContainer(
        image="postgres:18",
        username="target_admin",
        password="target_admin_password",
        dbname="target_test",
        driver="psycopg",
    ).with_command(
        "postgres -c shared_preload_libraries=pg_stat_statements "
        "-c compute_query_id=on -c pg_stat_statements.track=all"
    )
    with container:
        admin_dsn = container.get_connection_url(driver=None)
        host = container.get_container_host_ip()
        port = container.get_exposed_port(5432)
        with psycopg.connect(admin_dsn, autocommit=True) as connection:
            connection.execute("CREATE EXTENSION pg_stat_statements")
            connection.execute("CREATE ROLE monitor LOGIN PASSWORD 'monitor_password'")
            connection.execute("ALTER ROLE monitor SET default_transaction_read_only = on")
            connection.execute("GRANT pg_read_all_stats TO monitor")
            connection.execute("GRANT CONNECT ON DATABASE target_test TO monitor")
            connection.execute("CREATE ROLE workload LOGIN PASSWORD 'workload_password'")
            connection.execute("ALTER ROLE workload SET default_transaction_read_only = on")
            connection.execute("GRANT CONNECT ON DATABASE target_test TO workload")
            connection.execute(
                "CREATE TABLE demo_items (id bigint PRIMARY KEY, name text NOT NULL, value integer)"
            )
            connection.execute(
                "INSERT INTO demo_items "
                "SELECT n, 'item-' || n, n % 100 FROM generate_series(1, 5000) AS n"
            )
            connection.execute("ANALYZE demo_items")
            connection.execute("GRANT USAGE ON SCHEMA public TO monitor, workload")
            connection.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO monitor, workload")
        yield {
            "admin": admin_dsn,
            "monitor": f"postgresql://monitor:monitor_password@{host}:{port}/target_test",
            "workload": f"postgresql://workload:workload_password@{host}:{port}/target_test",
        }


def test_migrations_and_job_claiming(state_database_url: str) -> None:
    engine = create_engine(state_database_url)
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "scan_jobs" in tables
    assert "synthetic_workload_jobs" in tables
    assert "query_text" in {column["name"] for column in inspector.get_columns("findings")}
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        queued = enqueue_job(session, "integration-target", JobSource.MANUAL)
        claimed = claim_job(session, 30, 3)
        assert claimed is not None
        assert claimed.id == queued.id
        assert claimed.status == JobStatus.RUNNING


def test_pg_stat_statements_and_read_only_monitoring(target_database: dict[str, str]) -> None:
    with psycopg.connect(target_database["workload"], autocommit=True) as connection:
        for _ in range(12):
            connection.execute(
                "SELECT count(*) FROM demo_items WHERE lower(name) LIKE '%item%'"
            ).fetchone()
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute("DELETE FROM demo_items")

    adapter = PostgreSQLAdapter("target-test", target_database["monitor"])
    counters = adapter.collect_query_counters()
    observed = [counter for counter in counters if "lower(name)" in counter.query_text]
    assert observed
    assert observed[0].calls >= 12
    assert observed[0].dbid > 0
    assert observed[0].username == "workload"


def test_real_failed_insert_creates_execution_error_finding(
    state_database_url: str, tmp_path, monkeypatch
) -> None:
    with PostgresContainer(image="postgres:18", dbname="error_test").with_command(
        "postgres -c shared_preload_libraries=pg_stat_statements "
        "-c compute_query_id=on -c logging_collector=on -c log_destination=jsonlog "
        "-c log_timezone=UTC -c log_min_error_statement=panic -c log_error_verbosity=terse"
    ) as container:
        dsn = container.get_connection_url(driver=None)
        with psycopg.connect(dsn, autocommit=True, application_name="orders-import") as connection:
            username = connection.info.user
            connection.execute("CREATE EXTENSION pg_stat_statements")
            connection.execute("CREATE TABLE demo_writes (name text UNIQUE)")
            sql = "INSERT INTO demo_writes VALUES ('private-demo-value')"
            connection.execute(sql)
            with pytest.raises(psycopg.errors.UniqueViolation):
                connection.execute(sql)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = container.exec(["sh", "-c", 'cat "$PGDATA"/log/*.json'])
            if result.exit_code == 0 and b'"23505"' in result.output:
                break
            time.sleep(0.05)
        else:
            pytest.fail("PostgreSQL did not write the unique violation to its JSON log")
        (tmp_path / "postgres.json").write_bytes(result.output)
        monkeypatch.setenv("QS_INSERT_TEST_DSN", dsn)
        target = TargetConfig(
            id="insert-test",
            engine="postgresql",
            dsn_env="QS_INSERT_TEST_DSN",
            error_log_dir=tmp_path,
            error_log_database="error_test",
        )
        project = ProjectConfig(targets=[target], notifications={"console": False})
        factory = sessionmaker(create_engine(state_database_url), expire_on_commit=False)
        with factory() as session:
            job = ScanJob(target_id=target.id, status=JobStatus.RUNNING)
            session.add(job)
            session.flush()
            run_scan(session, job, target, project, Settings(_env_file=None))
            assert job.status == JobStatus.COMPLETED
            finding = session.scalars(select(Finding).where(Finding.target_id == target.id)).one()
            assert finding.anomaly_type == AnomalyType.EXECUTION_ERROR
            assert finding.current_evidence["sqlstate"] == "23505"
            assert finding.current_evidence["operation"] == "INSERT"
            [source] = finding.current_evidence["query_sources"]
            assert source["username"] == username
            assert source["client"] == "orders-import"
            assert not finding.query_text
            assert "private-demo-value" not in str(finding.current_evidence)


def test_real_collection_delta_finding_and_notification(
    state_database_url: str, target_database: dict[str, str]
) -> None:
    statement = "SELECT sum(value * value) FROM demo_items WHERE value >= 0"
    adapter = PostgreSQLAdapter("target-test", target_database["monitor"])
    factory = sessionmaker(create_engine(state_database_url), expire_on_commit=False)
    with psycopg.connect(target_database["workload"], autocommit=True) as connection:
        for _ in range(5):
            connection.execute(statement).fetchone()

    with factory() as session:
        baseline = ScanJob(target_id="target-test", source=JobSource.MANUAL)
        session.add(baseline)
        session.flush()
        baseline_metrics = collect_scan(session, baseline, adapter)
        assert not [m for m in baseline_metrics if "value * value" in m.query_text]
        session.commit()

    with psycopg.connect(target_database["workload"], autocommit=True) as connection:
        for _ in range(5):
            connection.execute(statement).fetchone()

    detection = DetectionConfig(
        min_calls_per_interval=10,
        expensive_query_mean_ms=0.0001,
        meaningful_latency_ms=10_000,
        temp_blocks_threshold=1_000_000,
        block_read_ratio_threshold=1,
    )
    with factory() as session:
        measured = ScanJob(target_id="target-test", source=JobSource.MANUAL)
        session.add(measured)
        session.flush()
        metrics = collect_scan(session, measured, adapter)
        metric = next(item for item in metrics if "value * value" in item.query_text)
        assert metric.calls == 10
        assert metric.sample_scope == "cumulative"
        anomalies = detect_anomalies(session, [metric], detection)
        events = apply_findings(session, measured, anomalies, detection)
        session.commit()
        assert [event.event for event in events] == ["new"]
        assert events[0].finding.query_text == metric.query_text
        assert events[0].finding.current_evidence["query_sources"][0]["username"] == "workload"

        class RecordingNotifier(Notifier):
            channel = "integration"

            def send(self, payload):
                assert payload["query_text"] == metric.query_text

        deliver_notification(session, measured, events[0].finding, "new", RecordingNotifier())
        assert session.scalar(
            select(NotificationDelivery).where(
                NotificationDelivery.finding_id == events[0].finding.id,
                NotificationDelivery.status == "delivered",
            )
        )


def test_scan_findings_query_works_with_postgresql_json(state_database_url: str) -> None:
    engine = create_engine(state_database_url)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        scan = ScanJob(target_id="airlines", source=JobSource.MANUAL, status=JobStatus.COMPLETED)
        finding = Finding(
            target_id="airlines",
            query_fingerprint=uuid4().hex.ljust(64, "0"),
            query_text="SELECT count(*) FROM demo_items WHERE lower(name) LIKE $1",
            anomaly_type=AnomalyType.LATENCY_REGRESSION,
            severity=Severity.HIGH,
            summary="integration finding",
            current_evidence={"ratio": 4.0},
        )
        session.add_all([scan, finding])
        session.flush()
        session.add(
            FindingObservation(
                finding_id=finding.id,
                scan_id=scan.id,
                severity=Severity.HIGH,
                evidence={"ratio": 4.0},
            )
        )
        session.commit()
        scan_id = scan.id
        finding_id = finding.id

    def override_session():
        with factory() as session:
            yield session

    app.dependency_overrides[session_dependency] = override_session
    settings = Settings(api_token="integration-fixture-token")
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        response = TestClient(app).get(
            f"/api/v1/findings?scan_id={scan_id}",
            headers={"Authorization": f"Bearer {settings.api_token}"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == str(finding_id)
        assert "demo_items" in body["items"][0]["query_text"]
    finally:
        app.dependency_overrides.pop(session_dependency, None)
        app.dependency_overrides.pop(get_settings, None)
