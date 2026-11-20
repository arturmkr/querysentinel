from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx
import httpx2
import pytest
from fastapi.testclient import TestClient
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from nicegui import ui
from nicegui.testing.user import User
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from querysentinel.api import app
from querysentinel.config import Settings, get_settings, load_project_config
from querysentinel.db import session_dependency
from querysentinel.mcp_server import create_mcp_http_app
from querysentinel.models import (
    Base,
    Finding,
    FindingObservation,
    Investigation,
    ScanJob,
    SyntheticWorkloadJob,
)
from querysentinel.schemas import AnomalyType, InvestigationStatus, JobSource, JobStatus, Severity


@pytest.fixture(autouse=True)
def api_credentials(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "api-fixture-token")
    get_settings.cache_clear()
    yield
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def make_client():
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def override_session():
        with factory() as session:
            yield session

    app.dependency_overrides[session_dependency] = override_session
    return TestClient(app), factory


def auth():
    return {"Authorization": f"Bearer {get_settings().api_token}"}


def test_auth_unknown_target_and_post_202(monkeypatch) -> None:
    monkeypatch.setenv(
        "AIRLINES_WORKLOAD_DATABASE_URL", "postgresql://read_only@example.invalid/airlines"
    )
    client, _ = make_client()
    assert client.get("/api/v1/targets").status_code == 401
    assert (
        client.post("/api/v1/scans", headers=auth(), json={"target_id": "missing"}).status_code
        == 404
    )
    response = client.post("/api/v1/scans", headers=auth(), json={"target_id": "airlines"})
    assert response.status_code == 202
    body = response.json()
    assert body["target_id"] == "airlines"
    assert body["status"] == "QUEUED"
    duplicate = client.post("/api/v1/scans", headers=auth(), json={"target_id": "airlines"})
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["scan_id"] == body["scan_id"]
    polled = client.get(f"/api/v1/scans/{body['scan_id']}", headers=auth())
    assert polled.status_code == 200
    listed = client.get(
        "/api/v1/scans?target_id=airlines&limit=1&status=QUEUED&source=manual",
        headers=auth(),
    )
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["scan_id"] == body["scan_id"]

    workload = client.post(
        "/api/v1/synthetic-workloads",
        headers=auth(),
        json={"target_id": "airlines", "queries": 3, "rounds": 2, "fresh": False},
    )
    assert workload.status_code == 202
    workload_body = workload.json()
    assert workload_body["status"] == "QUEUED"
    polled_workload = client.get(
        f"/api/v1/synthetic-workloads/{workload_body['job_id']}", headers=auth()
    )
    assert polled_workload.status_code == 200
    assert polled_workload.json()["query_count"] == 3
    history = client.get(
        "/api/v1/synthetic-workloads?target_id=airlines&limit=1&status=QUEUED", headers=auth()
    )
    assert history.json()["items"] == [polled_workload.json()]
    assert (
        client.get("/api/v1/synthetic-workloads?target_id=lego", headers=auth()).json()["total"]
        == 0
    )


def test_target_findings_are_isolated_and_paginated() -> None:
    client, factory = make_client()
    with factory() as session:
        scan = ScanJob(target_id="airlines", source=JobSource.MANUAL)
        session.add(scan)
        session.flush()
        for target in ("airlines", "lego"):
            finding = Finding(
                target_id=target,
                query_fingerprint=target[0] * 64,
                query_text="SELECT * FROM inventory WHERE name ILIKE $1",
                anomaly_type=AnomalyType.LATENCY_REGRESSION,
                severity=Severity.HIGH,
                summary="measured regression",
                current_evidence={"ratio": 4},
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
            )
            session.add(finding)
            session.flush()
            if target == "airlines":
                session.add(
                    FindingObservation(
                        finding_id=finding.id,
                        scan_id=scan.id,
                        severity=Severity.HIGH,
                        evidence={"ratio": 4},
                    )
                )
                session.add(
                    Investigation(
                        finding_id=finding.id,
                        scan_id=scan.id,
                        status=InvestigationStatus.SUCCESS,
                        model_name="test",
                        result={
                            "target_id": "airlines",
                            "scan_id": str(scan.id),
                            "query_fingerprint": finding.query_fingerprint,
                            "anomaly_type": "latency_regression",
                            "severity": "high",
                            "evidence": {"ratio": 4},
                            "suspected_causes": ["non-sargable text predicate"],
                            "remediation": ["consider an expression index"],
                            "verification_steps": ["compare EXPLAIN plans"],
                            "confidence": 0.8,
                            "status": "success",
                        },
                        input_tokens=100,
                        output_tokens=50,
                    )
                )
        session.commit()
    response = client.get(
        "/api/v1/findings?target_id=airlines&limit=1&severity=high", headers=auth()
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["target_id"] == "airlines"
    assert body["items"][0]["query_text"] == "SELECT * FROM inventory WHERE name ILIKE $1"
    detail = client.get(f"/api/v1/findings/{body['items'][0]['id']}", headers=auth())
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["latest_investigation"]["remediation"] == ["consider an expression index"]
    assert detail_body["investigation_status"] == "success"
    assert detail_body["investigation_input_tokens"] == 100
    invalid_page = client.get("/api/v1/findings?target_id=airlines&limit=201", headers=auth())
    assert invalid_page.status_code == 422
    scan_response = client.get("/api/v1/findings", params={"scan_id": str(scan.id)}, headers=auth())
    assert scan_response.status_code == 200
    assert scan_response.json()["total"] == 1


def test_nicegui_is_mounted_without_changing_rest_api() -> None:
    client, _ = make_client()
    response = client.get("/ui/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert get_settings().api_token not in response.text


def test_mcp_requires_the_api_bearer_token() -> None:
    client, _ = make_client()
    response = client.post("/mcp/", json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert (
        client.post(
            "/mcp/",
            headers={"Authorization": "Bearer wrong-token"},
            json={},
        ).status_code
        == 401
    )


@pytest.mark.asyncio
async def test_mcp_lists_tools_and_queues_a_scan(monkeypatch) -> None:
    _, factory = make_client()
    monkeypatch.setattr("querysentinel.mcp_server.get_session_factory", lambda: factory)
    headers = {"Authorization": f"Bearer {get_settings().api_token}"}
    mcp_server, mcp_app = create_mcp_http_app(get_settings())

    async with (
        mcp_server.session_manager.run(),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=mcp_app),
            base_url="http://127.0.0.1",
            headers=headers,
        ) as http_client,
    ):
        transport = streamable_http_client(
            "http://127.0.0.1/",
            http_client=http_client,
        )
        async with Client(transport, raise_exceptions=True) as mcp_client:
            tools = await mcp_client.list_tools()
            assert {tool.name for tool in tools.tools} == {
                "list_targets",
                "list_scans",
                "get_scan",
                "list_findings",
                "get_finding",
                "start_scan",
            }
            targets = await mcp_client.call_tool("list_targets", {})
            assert {item["id"] for item in targets.structured_content["items"]} == {
                "airlines",
                "lego",
            }

            started = await mcp_client.call_tool("start_scan", {"target_id": "airlines"})
            assert started.structured_content["created"] is True
            scan_id = started.structured_content["scan_id"]
            duplicate = await mcp_client.call_tool("start_scan", {"target_id": "airlines"})
            assert duplicate.structured_content == {
                **started.structured_content,
                "created": False,
            }
            scan = await mcp_client.call_tool("get_scan", {"scan_id": scan_id})
            assert scan.structured_content["status"] == "QUEUED"

            listed = await mcp_client.call_tool(
                "list_scans",
                {"target_id": "airlines", "status": "QUEUED"},
            )
            assert listed.structured_content["total"] == 1
            assert listed.structured_content["items"][0]["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_investigation_dialog_survives_dashboard_refresh(monkeypatch) -> None:
    _, factory = make_client()
    settings = Settings(api_token=get_settings().api_token, ui_admin_password="ui-test")
    monkeypatch.setattr("querysentinel.ui.get_settings", lambda: settings)
    monkeypatch.setattr(
        "querysentinel.ui._api_client",
        lambda settings: httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {settings.api_token}"},
        ),
    )
    target_id = load_project_config().targets[0].id
    monkeypatch.setenv(
        load_project_config().targets[0].workload_dsn_env,
        "postgresql://read_only@example.invalid/demo",
    )
    sql = "\n".join(["SELECT 1", *["-- " + "x" * 200] * 49, "-- end of full SQL"])
    with factory() as session:
        session.add(
            Finding(
                target_id=target_id,
                query_fingerprint="f" * 64,
                query_text=sql,
                anomaly_type=AnomalyType.LATENCY_REGRESSION,
                severity=Severity.HIGH,
                summary="Regression for dialog test",
                current_evidence={
                    "calls": 10,
                    "query_sources": [
                        {
                            "username": "orders",
                            "last_seen": datetime.now(UTC).isoformat(),
                            "occurrences": 10,
                        }
                    ],
                },
            )
        )
        session.commit()

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client,
    ):
        user = User(client)
        await user.open("/ui/")
        user.find(ui.input).type("wrong")
        user.find("Log in").click()
        await user.should_see("Invalid admin password")
        await user.should_not_see("Run synthetic workload")
        user.find(ui.input).type("ui-test")
        user.find("Log in").click()
        await user.should_see("Recent scans")
        await user.should_see("Latest 20")
        user.find("Run synthetic workload").click()
        await user.should_see("Synthetic workload")
        await user.should_see("Queued")
        with factory() as session:
            job = session.scalars(select(SyntheticWorkloadJob)).one()
            job.status = JobStatus.COMPLETED
            job.succeeded = 9
            job.failed = 1
            session.commit()
        user.find("Findings").click()
        await user.should_see("Open investigation")
        open_button = user.find("Open investigation")
        old_button = next(iter(open_button.elements))
        open_button.click()
        await user.should_see("Measured symptom")
        dialog = next(iter(user.find(ui.dialog).elements))
        assert dialog.value
        await user.should_see("Observed sources (latest sample)")
        await user.should_see("Copy full SQL")
        await user.should_see("Copy full investigation")
        assert any("end of full SQL" in code.content for code in user.find(ui.markdown).elements)
        assert any('"calls": 10' in code.content for code in user.find(ui.code).elements)
        await user.should_not_see(ui.json_editor)

        # Change the finding so the timer replaces its row while the dialog is open.
        with factory() as session:
            finding = session.scalars(select(Finding)).one()
            finding.summary = "Updated regression summary"
            session.commit()
        async with asyncio.timeout(5):
            while not old_button.is_deleted:
                await asyncio.sleep(0.05)
        await user.should_see("Open investigation")
        await user.should_see("Updated regression summary")
        assert not dialog.is_deleted
        assert dialog.value
        await user.should_see("Measured symptom")
        await user.should_see("Completed")
        await user.should_see("9 succeeded · 1 failed")
        user.find("Close").click()
        assert not dialog.value
        await user.open("/ui/")
        user.find(ui.input).type("ui-test")
        user.find("Log in").click()
        await user.should_see("Completed")
        await user.should_see("9 succeeded · 1 failed")
