"""Minimal NiceGUI operations view mounted into the existing FastAPI application."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from datetime import datetime
from pathlib import Path
from textwrap import shorten
from typing import Any
from uuid import UUID

import httpx
from fastapi import FastAPI
from nicegui import app as nicegui_app
from nicegui import ui

from querysentinel.config import Settings, get_settings
from querysentinel.schemas import (
    FindingDetail,
    FindingPage,
    FindingStatus,
    FindingSummary,
    JobStatus,
    QuerySource,
    ScanDetail,
    ScanPage,
    SyntheticWorkloadPage,
    SyntheticWorkloadResponse,
    TargetResponse,
)

SEVERITY_COLORS = {
    "low": ("blue-8", "white"),
    "medium": ("amber-5", "black"),
    "high": ("orange-7", "black"),
    "critical": ("red-8", "white"),
}
INVESTIGATION_FIELDS = (
    ("Suspected causes", "suspected_causes"),
    ("Hypotheses", "hypotheses"),
    ("Recommended remediation", "remediation"),
    ("How to verify", "verification_steps"),
)


def closure_details(finding: FindingSummary) -> str:
    if finding.status != FindingStatus.RESOLVED:
        return ""
    reason = "Closed by Max Age" if finding.resolution_reason == "max_age" else "Resolved"
    if finding.resolved_at:
        return f"{reason} · {finding.resolved_at.isoformat(sep=' ', timespec='seconds')}"
    return reason


def finding_badges(finding: FindingSummary) -> None:
    color, text_color = SEVERITY_COLORS.get(finding.severity, ("grey-7", "white"))
    ui.badge(finding.severity.title(), color=color, text_color=text_color)
    closure = closure_details(finding)
    badge = ui.badge(finding.status.title(), color="green-8" if closure else "grey-7")
    if closure:
        badge.tooltip(closure)


def highlighted_sql(sql: str, classes: str) -> None:
    # Match NiceGUI's code fences, without adding a copy button and timer to each preview.
    longest_run = max(map(len, re.findall(r"`+", sql)), default=0)
    fence = "`" * max(3, longest_run + 1)
    ui.markdown(f"{fence}sql\n{sql}\n{fence}").classes(f"w-full min-w-0 {classes}")


def source_label(source: QuerySource) -> str:
    name = source.username or "Unknown user"
    return f"{name} · {source.client}" if source.client else name


def source_description(source: QuerySource) -> str:
    count_label = (
        "logged slow executions" if source.observation_kind == "duration_log" else "observations"
    )
    return (
        f"{source_label(source)} · {source.occurrences} {count_label} "
        f"· last seen {display_time(source.last_seen)}"
    )


def display_time(value: datetime) -> str:
    return value.isoformat(sep=" ", timespec="seconds")


def _api_client(settings: Settings) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.ui_api_base_url,
        headers={"Authorization": f"Bearer {settings.api_token}"},
        timeout=5.0,
        trust_env=False,
    )


def install_ui(app: FastAPI) -> None:
    mount_path = "/ui"
    logo = Path(__file__).resolve().parents[2] / "docs/assets/querysentinel-logo.png"
    logo_url = None
    if logo.is_file():
        logo_url = nicegui_app.add_static_file(
            local_file=logo, url_path="/assets/querysentinel-logo.png"
        )

    @ui.page("/")
    def dashboard() -> None:
        settings = get_settings()
        authenticated = False
        targets: dict[str, TargetResponse] = {}
        selected_target: str | None = None
        workload_id: UUID | None = None
        workload_pending = False
        scan_pending = False

        ui.dark_mode(True)

        async def request(
            path: str,
            *,
            params: dict[str, str | int] | None = None,
            body: dict[str, str | int | bool] | None = None,
            notify: bool = False,
        ) -> Any:
            try:
                async with _api_client(settings) as client:
                    response = (
                        await client.get(f"/api/v1/{path}", params=params)
                        if body is None
                        else await client.post(f"/api/v1/{path}", json=body)
                    )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as exc:
                if notify:
                    message = "QuerySentinel API unavailable"
                    if isinstance(exc, httpx.HTTPStatusError):
                        try:
                            detail = exc.response.json().get("detail")
                            if isinstance(detail, dict):
                                detail = detail.get("message")
                            if isinstance(detail, str):
                                message = detail
                        except ValueError:
                            pass
                    ui.notify(message, type="warning")
                return None

        async def authenticate() -> None:
            nonlocal authenticated, selected_target
            if authenticated:
                return
            if not settings.ui_admin_password:
                login_status.set_text("Set UI_ADMIN_PASSWORD to enable dashboard sign-in")
                return
            valid = secrets.compare_digest(
                (password.value or "").encode(), settings.ui_admin_password.encode()
            )
            password.set_value("")
            if not valid:
                login_status.set_text("Invalid admin password")
                return
            response = await request("targets")
            if response is None:
                login_status.set_text("Could not load data sources from the API")
                return
            targets.update(
                {target.id: target for target in map(TargetResponse.model_validate, response)}
            )
            selected_target = next(iter(targets), None)
            authenticated = True
            target_select.set_options(list(targets), value=selected_target)
            login.set_visibility(False)
            dashboard_panel.set_visibility(True)
            await refresh_dashboard()

        with ui.column().classes(
            "mx-auto w-full max-w-xs min-h-[calc(100dvh_-_2rem)] items-center justify-center"
        ) as login:
            if logo_url:
                ui.image(logo_url).classes("w-28 h-28").props(
                    'fit=contain alt="QuerySentinel logo"'
                )
            ui.label("QuerySentinel").classes("text-h4")
            password = ui.input(
                "Admin password", password=True, password_toggle_button=True
            ).classes("w-full")
            password.on("keydown.enter", authenticate)
            ui.button("Log in", on_click=authenticate, icon="login").classes("w-full")
            login_status = ui.label().classes("text-negative text-center")

        async def start_scan() -> None:
            nonlocal scan_pending
            if not authenticated or selected_target is None or scan_pending:
                return
            scan_pending = True
            scan_button.disable()
            try:
                job = await request("scans", body={"target_id": selected_target}, notify=True)
                if job is not None:
                    ui.notify(f"Scan queued: {job['scan_id']}", type="positive")
            finally:
                scan_pending = False
            await refresh_scans_and_findings()

        async def start_workload() -> None:
            nonlocal workload_id, workload_pending
            if not authenticated or selected_target is None or workload_pending:
                return
            target_id = selected_target
            workload_pending = True
            workload_button.disable()
            try:
                job = await request(
                    "synthetic-workloads",
                    body={"target_id": target_id},
                    notify=True,
                )
                if job is not None and target_id == selected_target:
                    workload_id = SyntheticWorkloadResponse.model_validate(job).job_id
            finally:
                workload_pending = False
            await refresh_workload()

        async def refresh_workload() -> None:
            nonlocal workload_id
            if not authenticated or selected_target is None:
                return
            target_id, job_id = selected_target, workload_id
            target = targets[target_id]
            if job_id is None:
                response = await request(
                    "synthetic-workloads", params={"target_id": target_id, "limit": 1}
                )
                items = (
                    SyntheticWorkloadPage.model_validate(response).items
                    if response is not None
                    else []
                )
                job = items[0] if items else None
            else:
                response = await request(f"synthetic-workloads/{job_id}")
                job = (
                    SyntheticWorkloadResponse.model_validate(response)
                    if response is not None
                    else None
                )
            if (target_id, job_id) != (selected_target, workload_id):
                return
            if response is None:
                workload_status.set_text("Could not load synthetic workload status")
                return
            active = False
            message = ""
            if job:
                workload_id = job.job_id
                active = job.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                message = f"Synthetic workload: {job.status.title()}"
                if not active:
                    message += f" · {job.succeeded} succeeded · {job.failed} failed"
                    if job.error:
                        message += f" · {job.error}"
            workload_status.set_text(message)
            workload_button.set_enabled(
                target.enabled
                and target.synthetic_workload_enabled
                and not active
                and not workload_pending
            )
            workload_timer.active = active

        async def refresh_dashboard() -> None:
            nonlocal workload_id
            if not authenticated:
                return
            workload_id = None
            await asyncio.gather(refresh_workload(), refresh_scans_and_findings())

        async def change_target(event) -> None:
            nonlocal selected_target
            if not authenticated or event.value not in targets or event.value == selected_target:
                return
            selected_target = event.value
            workload_button.disable()
            workload_status.set_text("")
            scan_data.refresh([])
            finding_data.refresh([])
            await refresh_dashboard()

        with ui.dialog() as investigation_dialog, ui.card().classes("w-full max-w-5xl min-w-0"):
            investigation_content = ui.column().classes("w-full min-w-0")
            ui.button("Close", on_click=investigation_dialog.close)

        async def show_finding(finding_id: UUID) -> None:
            if not authenticated:
                return
            response = await request(f"findings/{finding_id}", notify=True)
            if response is None:
                return
            finding = FindingDetail.model_validate(response)
            payload = finding.latest_investigation
            error = finding.investigation_error
            evidence = json.dumps(finding.current_evidence, indent=2)
            sql = finding.query_text
            closure = closure_details(finding)
            last_seen = f"Last detected: {display_time(finding.last_seen)}"
            source_lines = [source_description(source) for source in finding.query_sources]
            sections = [
                (title, getattr(payload, field))
                for title, field in INVESTIGATION_FIELDS
                if payload and getattr(payload, field)
            ]
            if payload:
                status = f"AI investigation: {payload.status.replace('_', ' ')}"
            elif error:
                status = f"Investigation unavailable: {error}"
            else:
                status = "No AI investigation has been recorded yet"
            report = [
                finding.summary,
                f"Finding: {finding.id}\nTarget: {finding.target_id}\nType: {finding.anomaly_type}"
                f"\nRisk: {finding.severity.title()}\nStatus: {finding.status.title()}",
                last_seen,
                "Observed sources (latest sample)\n"
                + ("\n".join(source_lines) if source_lines else "Unknown"),
                f"Observed SQL\n{sql or 'Unavailable'}",
                f"Measured evidence\n{evidence}",
                status,
            ]
            if closure:
                report.insert(3, closure)
            for title, items in sections:
                report.append("\n".join([title, *(f"- {item}" for item in items)]))
            report_text = "\n\n".join(report)

            investigation_content.clear()
            with investigation_content:
                with ui.column().classes("w-full min-w-0 gap-1"):
                    ui.label("Measured symptom").classes("text-subtitle1")
                    ui.label(finding.summary).classes("text-h5 break-words")
                    with ui.row().classes("items-center gap-2"):
                        finding_badges(finding)
                        ui.label(finding.anomaly_type.replace("_", " "))
                    if closure:
                        ui.label(closure).classes("text-sm")
                    ui.label(last_seen).classes("text-sm")
                with ui.column().classes("w-full min-w-0 gap-1"):
                    ui.label("Observed sources (latest sample)").classes("text-subtitle1")
                    for line in source_lines or ["Unknown"]:
                        ui.label(line).classes("break-words")
                with ui.row().classes("gap-2"):
                    ui.button(
                        "Copy full investigation",
                        on_click=lambda: ui.clipboard.write(report_text),
                        icon="content_copy",
                    ).props("flat")
                    if sql:
                        ui.button(
                            "Copy full SQL",
                            on_click=lambda: ui.clipboard.write(sql),
                            icon="content_copy",
                        ).props("flat")
                with ui.column().classes("w-full min-w-0 gap-1"):
                    ui.label("Observed SQL").classes("text-subtitle1")
                    if sql:
                        highlighted_sql(
                            sql,
                            "max-h-48 overflow-y-auto overflow-x-hidden "
                            "[&_pre]:whitespace-pre-wrap [&_pre]:[overflow-wrap:anywhere]",
                        )
                    else:
                        ui.label("SQL text is unavailable for this execution error")
                with ui.column().classes("w-full min-w-0 gap-1"):
                    ui.label("Measured evidence").classes("text-subtitle1")
                    ui.code(evidence, language="json").classes("w-full max-w-full overflow-x-auto")
                ui.label(status).classes("text-warning" if error else "text-sm")
                for title, items in sections:
                    with ui.column().classes("w-full min-w-0 gap-1"):
                        ui.label(title).classes("text-subtitle1")
                        for item in items:
                            with ui.row(wrap=False).classes("w-full gap-2"):
                                ui.label("•")
                                ui.label(item).classes("min-w-0 whitespace-pre-line break-words")
            investigation_dialog.open()

        with ui.column().classes("w-full min-w-0") as dashboard_panel:
            ui.label("QuerySentinel").classes("text-h6")
            with ui.row().classes("items-end"):
                target_select = ui.select([], label="Data source", on_change=change_target).classes(
                    "w-56 max-w-full"
                )
                scan_button = ui.button("Start scan", on_click=start_scan, icon="search")
                scan_button.disable()
                workload_button = ui.button(
                    "Run synthetic workload", on_click=start_workload, icon="speed"
                )
                workload_button.disable()
                ui.button("Refresh", on_click=refresh_dashboard, icon="refresh")
            workload_status = ui.label()
            load_status = ui.label()
        dashboard_panel.set_visibility(False)
        workload_timer = ui.timer(3.0, refresh_workload, active=False, immediate=False)

        @ui.refreshable
        def scan_data(scans: list[ScanDetail]) -> None:
            active = next(
                (scan for scan in scans if scan.status in (JobStatus.QUEUED, JobStatus.RUNNING)),
                None,
            )
            ui.label("Current scan").classes("text-h6")
            if active:
                ui.linear_progress(value=None)
                ui.label(f"{active.status}: {active.scan_id}")
            elif scans:
                ui.label(f"Last scan: {scans[0].status} at {scans[0].created_at}")
            else:
                ui.label("No scans yet")

            ui.label("Recent scans (latest 20)").classes("text-h6")
            ui.table(
                columns=[
                    {"name": "id", "label": "Scan", "field": "id"},
                    {"name": "status", "label": "Status", "field": "status"},
                    {"name": "source", "label": "Source", "field": "source"},
                    {"name": "created", "label": "Created", "field": "created"},
                ],
                rows=[
                    {
                        "id": str(scan.scan_id),
                        "status": scan.status,
                        "source": scan.source,
                        "created": scan.created_at.isoformat(),
                    }
                    for scan in scans
                ],
                row_key="id",
            ).classes("w-full")

        @ui.refreshable
        def finding_data(findings: list[FindingSummary]) -> None:
            ui.label("Recent findings (latest 50)").classes("text-h6")
            if not findings:
                ui.label("No findings for this target")
            for finding in findings:
                with ui.card().classes("w-full"):
                    with ui.row().classes("w-full items-center"):
                        ui.label(finding.summary).classes("text-subtitle1")
                        finding_badges(finding)
                    source = (
                        source_label(finding.query_sources[0])
                        if finding.query_sources
                        else "Unknown"
                    )
                    if len(finding.query_sources) > 1:
                        source += f" (+{len(finding.query_sources) - 1} more)"
                    ui.label(
                        f"Source: {source} · Last detected: {display_time(finding.last_seen)}"
                    ).classes("text-sm")
                    if finding.query_text:
                        highlighted_sql(
                            shorten(finding.query_text, width=160, placeholder="..."),
                            "overflow-hidden [&_pre]:truncate",
                        )
                    ui.button(
                        "Open investigation",
                        on_click=lambda finding_id=finding.id: show_finding(finding_id),
                    )

        with dashboard_panel:
            with ui.tabs().classes("w-full") as tabs:
                scans_tab = ui.tab("Scans")
                findings_tab = ui.tab("Findings")
            with ui.tab_panels(tabs, value=scans_tab, keep_alive=True).classes("w-full min-w-0"):
                with ui.tab_panel(scans_tab):
                    scan_data([])
                with ui.tab_panel(findings_tab):
                    finding_data([])

        async def refresh_scans_and_findings() -> None:
            if not authenticated or selected_target is None:
                return
            target_id = selected_target
            scan_button.set_enabled(targets[target_id].enabled and not scan_pending)
            scans, findings = await asyncio.gather(
                request("scans", params={"target_id": target_id, "limit": 20}),
                request("findings", params={"target_id": target_id, "limit": 50}),
            )
            if target_id != selected_target:
                return
            load_status.set_text(
                "Could not refresh dashboard" if scans is None or findings is None else ""
            )
            if scans is not None:
                scan_data.refresh(ScanPage.model_validate(scans).items)
            if findings is not None:
                finding_data.refresh(FindingPage.model_validate(findings).items)

        ui.timer(3.0, refresh_scans_and_findings)

    ui.run_with(
        app,
        mount_path=mount_path,
        title="QuerySentinel",
        dark=True,
        show_welcome_message=False,
    )
