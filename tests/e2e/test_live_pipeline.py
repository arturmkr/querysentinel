from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import yaml
from alembic.config import Config
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from testcontainers.community.postgres import PostgresContainer

from alembic import command
from querysentinel.config import get_settings
from querysentinel.models import Investigation, NotificationDelivery

pytestmark = pytest.mark.live_ai

def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _poll_json(
    client: httpx.Client, path: str, headers: dict[str, str], timeout: float = 120
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(path, headers=headers)
        response.raise_for_status()
        payload = response.json()
        if payload["status"] in {"COMPLETED", "FAILED"}:
            return payload
        time.sleep(0.5)
    raise TimeoutError(f"timed out polling {path}")


@pytest.fixture(scope="session")
def live_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    if os.getenv("LIVE_AI_TESTS", "").lower() != "true":
        pytest.skip("set LIVE_AI_TESTS=true to enable paid live E2E")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        pytest.skip("OPENAI_API_KEY is required for paid live E2E")
    model = os.getenv("AI_MODEL")
    if not model:
        pytest.skip("AI_MODEL must select the live model")

    input_price = os.getenv("LIVE_AI_INPUT_PRICE_PER_MILLION_USD")
    output_price = os.getenv("LIVE_AI_OUTPUT_PRICE_PER_MILLION_USD")
    if input_price is None or output_price is None:
        pytest.skip("configure current model input/output prices for cost admission control")
    max_requests = int(os.getenv("LIVE_AI_MAX_REQUESTS_PER_TEST", "5"))
    max_output = int(os.getenv("LIVE_AI_MAX_OUTPUT_TOKENS", "2000"))
    max_input_estimate = int(os.getenv("LIVE_AI_MAX_INPUT_TOKENS_ESTIMATE", "12000"))
    budget = float(os.getenv("LIVE_AI_MAX_TEST_BUDGET_USD", "0.05"))
    admission_cost = (
        max_input_estimate * float(input_price) + max_output * float(output_price)
    ) / 1_000_000
    if admission_cost > budget:
        pytest.skip(
            f"configured worst-case estimate ${admission_cost:.4f} exceeds ${budget:.4f} budget"
        )

    root = Path(__file__).parents[2]
    dump = Path(
        subprocess.check_output(
            [sys.executable, str(root / "scripts" / "demo_dataset.py")],
            cwd=root,
            text=True,
        ).strip()
    )
    workdir = tmp_path_factory.mktemp("live-querysentinel")
    state = PostgresContainer(
        image="postgres:18",
        username="sentinel_live",
        password="sentinel_live_password",
        dbname="sentinel_live",
        driver="psycopg",
    )
    target = PostgresContainer(
        image="postgres:18",
        username="target_admin",
        password="target_admin_password",
        dbname="lego_live",
        driver="psycopg",
    ).with_command(
        "postgres -c shared_preload_libraries=pg_stat_statements "
        "-c compute_query_id=on -c pg_stat_statements.track=all"
    )
    target.with_volume_mapping(str(dump), "/tmp/lego.sql", mode="ro")
    state.start()
    target.start()
    processes: list[subprocess.Popen[str]] = []
    try:
        state_url = state.get_connection_url()
        admin_dsn = target.get_connection_url(driver=None)
        target_host = target.get_container_host_ip()
        target_port = target.get_exposed_port(5432)
        monitor_dsn = (
            f"postgresql://sentinel_monitor:monitor_password@{target_host}:{target_port}/lego_live"
        )
        workload_dsn = (
            f"postgresql://demo_workload:workload_password@{target_host}:{target_port}/lego_live"
        )
        exit_code, output = target.exec(
            [
                "psql",
                "-U",
                "target_admin",
                "-d",
                "lego_live",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "/tmp/lego.sql",
            ]
        )
        assert exit_code == 0, output.decode(errors="replace")[-4000:]
        with psycopg.connect(admin_dsn, autocommit=True) as connection:
            connection.execute("CREATE EXTENSION pg_stat_statements")
            connection.execute("CREATE ROLE sentinel_monitor LOGIN PASSWORD 'monitor_password'")
            connection.execute("ALTER ROLE sentinel_monitor SET default_transaction_read_only=on")
            connection.execute("GRANT pg_read_all_stats TO sentinel_monitor")
            connection.execute("GRANT CONNECT ON DATABASE lego_live TO sentinel_monitor")
            connection.execute("CREATE ROLE demo_workload LOGIN PASSWORD 'workload_password'")
            connection.execute("ALTER ROLE demo_workload SET default_transaction_read_only=on")
            connection.execute("GRANT CONNECT ON DATABASE lego_live TO demo_workload")
            connection.execute("GRANT USAGE ON SCHEMA public TO sentinel_monitor, demo_workload")
            connection.execute(
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO sentinel_monitor, demo_workload"
            )
            connection.execute("ANALYZE")
            counts = {
                table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("lego_sets", "lego_parts", "lego_inventory_parts")
            }
        assert counts == {
            "lego_sets": 11673,
            "lego_parts": 25993,
            "lego_inventory_parts": 580251,
        }

        config_path = workdir / "config.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "targets": [
                        {
                            "id": "lego-live",
                            "engine": "postgresql",
                            "dsn_env": "LEGO_LIVE_DATABASE_URL",
                            "enabled": True,
                            "schedule": "0 0 1 1 *",
                        }
                    ],
                    "detection": {
                        "min_calls_per_interval": 3,
                        "meaningful_latency_ms": 0,
                        "latency_regression_factor": 2,
                        "workload_regression_factor": 2,
                        "expensive_query_mean_ms": 0.01,
                        "temp_blocks_threshold": 1,
                        "block_read_ratio_threshold": 0.01,
                        "max_llm_investigations_per_scan": int(
                            os.getenv("LIVE_AI_MAX_INVESTIGATIONS", "1")
                        ),
                    },
                    "notifications": {"console": True, "webhook": False},
                }
            )
        )
        api_token = "live-e2e-token"
        env = os.environ.copy()
        env.update(
            {
                "SENTINEL_DATABASE_URL": state_url,
                "LEGO_LIVE_DATABASE_URL": monitor_dsn,
                "CONFIG_PATH": str(config_path),
                "API_TOKEN": api_token,
                "OPENAI_API_KEY": api_key,
                "AI_MODEL": model,
                "LLM_MAX_REQUESTS": str(max_requests),
                "LLM_MAX_OUTPUT_TOKENS": str(max_output),
                "LLM_MAX_TOKENS": str(max_input_estimate + max_output),
            }
        )
        previous_state_url = os.environ.get("SENTINEL_DATABASE_URL")
        os.environ["SENTINEL_DATABASE_URL"] = state_url
        get_settings.cache_clear()
        command.upgrade(Config("alembic.ini"), "head")
        if previous_state_url is None:
            os.environ.pop("SENTINEL_DATABASE_URL", None)
        else:
            os.environ["SENTINEL_DATABASE_URL"] = previous_state_url
        get_settings.cache_clear()

        port = _free_port()
        api_log = (workdir / "api.log").open("w")
        worker_log = (workdir / "worker.log").open("w")
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "querysentinel.api:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=root,
                env=env,
                stdout=api_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
        processes.append(
            subprocess.Popen(
                [sys.executable, "-m", "querysentinel.worker"],
                cwd=root,
                env=env,
                stdout=worker_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        )
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{base_url}/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.25)
        else:
            raise RuntimeError(f"FastAPI did not start; see {api_log.name}")
        yield {
            "base_url": base_url,
            "headers": {"Authorization": f"Bearer {api_token}"},
            "workload_dsn": workload_dsn,
            "state_url": state_url,
            "budget": budget,
            "input_price": float(input_price),
            "output_price": float(output_price),
        }
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        target.stop()
        state.stop()


def test_live_api_worker_postgres_ai_pipeline(live_environment: dict[str, Any]) -> None:
    query = """
        SELECT p.name, c.name AS color, sum(ip.quantity) AS quantity
          FROM lego_parts p
          JOIN lego_inventory_parts ip ON ip.part_num = p.part_num
          JOIN lego_colors c ON c.id = ip.color_id
         WHERE lower(p.name) LIKE '%brick%'
         GROUP BY p.name, c.name
         ORDER BY quantity DESC
         LIMIT 50
    """
    headers = live_environment["headers"]
    with httpx.Client(base_url=live_environment["base_url"], timeout=30) as client:
        with psycopg.connect(live_environment["workload_dsn"], autocommit=True) as connection:
            connection.execute(query).fetchall()

        baseline = client.post("/api/v1/scans", json={"target_id": "lego-live"}, headers=headers)
        assert baseline.status_code == 202
        baseline_result = _poll_json(client, f"/api/v1/scans/{baseline.json()['scan_id']}", headers)
        assert baseline_result["status"] == "COMPLETED", baseline_result

        with psycopg.connect(live_environment["workload_dsn"], autocommit=True) as connection:
            for _ in range(5):
                connection.execute(query).fetchall()

        response = client.post("/api/v1/scans", json={"target_id": "lego-live"}, headers=headers)
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        result = _poll_json(client, f"/api/v1/scans/{scan_id}", headers, timeout=180)
        assert result["status"] == "COMPLETED", result

        findings = client.get("/api/v1/findings", params={"scan_id": scan_id}, headers=headers)
        findings.raise_for_status()
        items = findings.json()["items"]
        assert items
        assert all(item["target_id"] == "lego-live" for item in items)
        matching = next(item for item in items if "lego_inventory_parts" in item["query_text"])
        detail = client.get(f"/api/v1/findings/{matching['id']}", headers=headers)
        detail.raise_for_status()
        payload = detail.json()
        assert payload["latest_investigation"] is not None, payload
        investigation = payload["latest_investigation"]
        assert investigation["evidence"]
        assert investigation["remediation"] or investigation["verification_steps"]

    input_tokens = payload["investigation_input_tokens"] or 0
    output_tokens = payload["investigation_output_tokens"] or 0
    estimated_cost = (
        input_tokens * live_environment["input_price"]
        + output_tokens * live_environment["output_price"]
    ) / 1_000_000
    print(
        f"live AI usage: input={input_tokens}, output={output_tokens}, "
        f"estimated_cost=${estimated_cost:.6f}"
    )

    engine = create_engine(live_environment["state_url"])
    with Session(engine) as session:
        assert session.scalar(select(Investigation).where(Investigation.result.is_not(None)))
        assert session.scalar(
            select(NotificationDelivery).where(NotificationDelivery.status == "delivered")
        )
