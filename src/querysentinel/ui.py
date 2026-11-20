"""NiceGUI operations dashboard mounted into the existing FastAPI application."""

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

WIDTH = "qs-width mx-auto w-full px-4 sm:px-8"
SURFACE = "qs-surface w-full min-w-0"
SECONDARY_BUTTON = "qs-secondary"
BUTTON = "unelevated no-caps"
FIELD = "outlined dense hide-bottom-space"
MUTED = "text-sm text-slate-400"
SCAN_LIMIT = 20
FINDING_LIMIT = 50
SEVERITY_TONES = {"low": "blue", "medium": "amber", "high": "orange", "critical": "rose"}
JOB_TONES = {
    JobStatus.QUEUED: "amber",
    JobStatus.RUNNING: "blue",
    JobStatus.COMPLETED: "green",
    JobStatus.FAILED: "rose",
}
INVESTIGATION_FIELDS = (
    ("Suspected causes", "suspected_causes"),
    ("Hypotheses", "hypotheses"),
    ("Recommended remediation", "remediation"),
    ("How to verify", "verification_steps"),
)

DASHBOARD_CSS = """
body.qs-body {
    background: radial-gradient(ellipse 850px 450px at 22% 0%, #15243c 0%, transparent 100%),
                #0c121e;
    color: #ecf2fb;
    font-family: 'Inter', system-ui, sans-serif;
    --qs-edge: #28354a;
    --qs-surface: #131d2d;
}
.qs-width { max-width: 1248px; }
.qs-header { background: #0e1726; border-bottom: 1px solid var(--qs-edge); }
.qs-brand-mark {
    background: #142841;
    border: 1px solid #274668;
    border-radius: 12px;
    color: #7dd3fc;
}
.qs-surface, .q-card.qs-surface {
    background: var(--qs-surface);
    border: 1px solid var(--qs-edge);
    border-radius: 16px;
}
.qs-login-card {
    box-shadow: inset 0 1px #7dd3fc33, 0 28px 70px #0005;
    background: linear-gradient(160deg, #192a42 0%, #131d2d 55%) !important;
}
.qs-secondary {
    background: #182538;
    border: 1px solid #34465e;
    color: #e0eafb;
}
.qs-body .q-btn { border-radius: 9px; font-weight: 600; }
.qs-body .q-btn:focus-visible, .qs-body .q-tab:focus-visible {
    outline: 2px solid #7dd3fc;
    outline-offset: -2px;
}
.qs-body .q-field--outlined .q-field__control { border-radius: 9px; }
.qs-body .q-field--dark .q-field__control::before { border-color: #3c506a; }
.qs-body .q-field--dark .q-field__label { color: #a4b5cc; }
.qs-metric {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    grid-template-areas: "label icon" "value value" "detail detail";
    align-items: center;
    gap: 8px;
    min-height: 128px;
    box-shadow: inset 0 1px #7dd3fc26;
}
.qs-metric-label { grid-area: label; }
.qs-metric-icon { grid-area: icon; }
.qs-metric-value { grid-area: value; }
.qs-metric-detail { grid-area: detail; }
.qs-blue { color: #93c5fd; background: #60a5fa20; }
.qs-amber { color: #fcd282; background: #fbbf2420; }
.qs-orange { color: #fdba92; background: #fb923c24; }
.qs-rose { color: #fda4b9; background: #fb718523; }
.qs-green { color: #86efc5; background: #34d39920; }
.qs-slate { color: #c5d3e6; background: #94a3b81e; }
.qs-divider { border-color: var(--qs-edge); }
.qs-table thead, .qs-finding:hover { background: #0d1625; }
.qs-table tbody tr:hover, .qs-inspect:hover { background: #1b293c; }
.qs-table th, .qs-table td { padding: 12px 20px; }
.qs-sql {
    background: #0c1524;
    border: 1px solid #26374c;
    border-radius: 9px;
    padding: 10px 12px;
}
.qs-sql pre { margin: 0; font-size: 12px; line-height: 1.55; }
.qs-sql .codehilite { margin: 0; }
.qs-sql .codehilite pre { background: transparent; padding: 0; }
.qs-sql-preview pre { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.qs-sql-detail { max-height: 13rem; overflow: auto; }
.qs-sql-detail pre { white-space: pre-wrap; overflow-wrap: anywhere; }
.qs-evidence .nicegui-code-copy { opacity: .8; }
.q-card.qs-investigation {
    width: min(860px, calc(100vw - 32px));
    max-width: none;
    box-shadow: 0 24px 80px #0008;
}
.qs-dialog-header { background: var(--qs-surface); }
@media (max-width: 639px) {
    .qs-actions .q-btn { padding-inline: 8px; }
    .qs-actions .q-btn .q-icon { margin-right: 6px; font-size: 18px; }
    .qs-metric {
        min-height: 0;
        grid-template-columns: auto minmax(0, 1fr) auto;
        grid-template-areas: "icon label value" "icon detail detail";
        gap: 2px 10px;
        padding-block: 11px;
    }
    .qs-metric-value { font-size: 16px; text-align: right; }
}
"""


def closure_details(finding: FindingSummary) -> str:
    if finding.status != FindingStatus.RESOLVED:
        return ""
    reason = "Closed by Max Age" if finding.resolution_reason == "max_age" else "Resolved"
    if finding.resolved_at:
        return f"{reason} · {finding.resolved_at.isoformat(sep=' ', timespec='seconds')}"
    return reason


def badge(label: str, tone: str) -> ui.label:
    return ui.label(label).classes(
        f"qs-{tone} inline-flex items-center rounded-full px-2.5 py-1 "
        "text-xs font-semibold leading-tight whitespace-nowrap"
    )


def finding_badges(finding: FindingSummary) -> None:
    badge(finding.severity.title(), SEVERITY_TONES.get(finding.severity, "slate"))
    closure = closure_details(finding)
    status_badge = badge(finding.status.title(), "green" if closure else "slate")
    if closure:
        status_badge.tooltip(closure)


def metric(label: str, icon: str, tone: str) -> tuple[ui.label, ui.label]:
    with ui.element("div").classes(f"{SURFACE} qs-metric px-4 sm:p-5"):
        ui.label(label).classes("qs-metric-label text-sm font-medium text-slate-300")
        ui.icon(icon).classes(f"qs-metric-icon qs-{tone} rounded-lg p-2 text-[19px]")
        value = ui.label("—").classes(
            "qs-metric-value text-2xl font-semibold leading-none tracking-tight tabular-nums"
        )
        detail = ui.label().classes(f"qs-metric-detail {MUTED} [overflow-wrap:anywhere]")
    return value, detail


def empty_state(icon: str, message: str) -> None:
    with ui.row().classes("w-full items-center justify-center gap-3 px-5 py-12"):
        ui.icon(icon).classes("qs-slate rounded-xl p-2.5 text-xl")
        ui.label(message).classes(MUTED).props("role=status")


def highlighted_sql(sql: str, classes: str) -> None:
    # Match NiceGUI's code fences, without adding a copy button and timer to each preview.
    longest_run = max(map(len, re.findall(r"`+", sql)), default=0)
    fence = "`" * max(3, longest_run + 1)
    ui.markdown(f"{fence}postgresql\n{sql}\n{fence}").classes(f"qs-sql w-full min-w-0 {classes}")


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


def compact_time(value: datetime) -> ui.label:
    return (
        ui.label(value.strftime("%d %b %Y · %H:%M %Z").rstrip())
        .classes("whitespace-nowrap tabular-nums")
        .tooltip(display_time(value))
    )


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
        recent_scans: list[ScanDetail] | None = None
        recent_findings: list[FindingSummary] | None = None

        ui.dark_mode(True)
        ui.colors(primary="#285dc1")
        ui.add_css(DASHBOARD_CSS)
        ui.query("body").classes("qs-body")
        ui.query(".nicegui-content").classes("!p-0 !gap-0")

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
            target_select.set_enabled(bool(targets))
            login.set_visibility(False)
            dashboard_panel.set_visibility(True)
            await refresh_dashboard()

        with (
            ui.element("main").classes(
                "grid min-h-[100dvh] w-full place-items-center px-4 py-8"
            ) as login,
            ui.column().classes(
                f"{SURFACE} qs-login-card max-w-[420px] items-center gap-6 p-6 sm:p-9"
            ),
        ):
            with ui.column().classes("w-full items-center gap-3 text-center"):
                if logo_url:
                    ui.image(logo_url).classes("h-20 w-20").props('fit=contain alt=""')
                else:
                    ui.icon("monitor_heart").classes("qs-brand-mark p-3 text-3xl")
                ui.label("QuerySentinel").props("role=heading aria-level=1").classes(
                    "m-0 text-3xl font-semibold tracking-tight"
                )
                ui.label("PostgreSQL query monitoring").classes(MUTED)
            with ui.column().classes("w-full gap-3"):
                password = (
                    ui.input("Admin password", password=True, password_toggle_button=True)
                    .props(f"{FIELD} autocomplete=current-password")
                    .classes("w-full")
                )
                password.on("keydown.enter", authenticate)
                ui.button("Log in", on_click=authenticate, icon="login").props(BUTTON).classes(
                    "min-h-10 w-full"
                )
                login_status = (
                    ui.label()
                    .classes("w-full text-center text-sm text-rose-300")
                    .props("role=alert")
                )

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
                workload_detail.set_text("Could not load workload status")
                return
            active = False
            available = target.enabled and target.synthetic_workload_enabled
            status, detail = (
                ("No runs yet", "Ready to run") if available else ("Disabled", "For this source")
            )
            if job:
                workload_id = job.job_id
                active = job.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                status = job.status.title()
                detail = (
                    f"{job.query_count} queries · {job.rounds} rounds"
                    if active
                    else f"{job.succeeded} succeeded · {job.failed} failed"
                )
            workload_status.set_text(status)
            workload_detail.set_text(detail)
            workload_error.set_text((job.error or "") if job else "")
            workload_error.set_visibility(bool(job and job.error))
            workload_button.set_enabled(available and not active and not workload_pending)
            workload_timer.active = active

        async def refresh_dashboard() -> None:
            nonlocal workload_id
            if not authenticated:
                return
            if selected_target is None:
                load_status.set_text("No data sources configured")
                load_status.set_visibility(True)
                scan_data.refresh([])
                finding_data.refresh([])
                return
            workload_id = None
            await asyncio.gather(refresh_workload(), refresh_scans_and_findings())

        async def change_target(event) -> None:
            nonlocal selected_target, recent_scans, recent_findings
            if not authenticated or event.value not in targets or event.value == selected_target:
                return
            selected_target = event.value
            recent_scans = recent_findings = None
            workload_button.disable()
            workload_timer.deactivate()
            workload_status.set_text("—")
            workload_detail.set_text("")
            workload_error.set_visibility(False)
            update_overview()
            scan_data.refresh(None)
            finding_data.refresh(None)
            await refresh_dashboard()

        with (
            ui.dialog().props('aria-label="Investigation details"') as investigation_dialog,
            ui.card().classes(f"{SURFACE} qs-investigation !gap-0 !p-0"),
        ):
            with ui.row().classes(
                "qs-dialog-header qs-divider sticky top-0 z-10 w-full flex-nowrap "
                "items-center justify-between border-b px-5 py-3 sm:px-7"
            ):
                with ui.row(wrap=False).classes("items-center gap-3"):
                    ui.icon("manage_search").classes("qs-blue rounded-lg p-2 text-xl")
                    ui.label("Investigation details").classes("font-semibold")
                ui.button("Close", on_click=investigation_dialog.close, color=None).props(
                    "flat no-caps"
                ).classes("text-slate-300")
            investigation_content = ui.column().classes("w-full min-w-0 gap-5 p-5 sm:p-7")

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
                with ui.column().classes("w-full min-w-0 gap-3"):
                    with ui.row().classes("w-full items-center gap-2"):
                        finding_badges(finding)
                        ui.label(finding.anomaly_type.replace("_", " ").capitalize()).classes(MUTED)
                    ui.label("Measured symptom").classes("text-sm font-medium text-slate-400")
                    ui.label(finding.summary).classes(
                        "text-xl font-semibold leading-snug tracking-tight [overflow-wrap:anywhere]"
                    )
                    ui.label(last_seen).classes(MUTED)
                    if closure:
                        ui.label(closure).classes("text-sm text-emerald-300")
                with ui.row().classes("w-full gap-2"):
                    ui.button(
                        "Copy full investigation",
                        on_click=lambda: ui.clipboard.write(report_text),
                        icon="content_copy",
                        color=None,
                    ).props(BUTTON).classes(SECONDARY_BUTTON)
                    if sql:
                        ui.button(
                            "Copy full SQL",
                            on_click=lambda: ui.clipboard.write(sql),
                            icon="content_copy",
                            color=None,
                        ).props(BUTTON).classes(SECONDARY_BUTTON)
                with ui.column().classes("qs-divider w-full min-w-0 gap-2 border-t pt-4"):
                    ui.label("Observed sources (latest sample)").classes("font-semibold")
                    for line in source_lines or ["Unknown"]:
                        ui.label(line).classes(f"{MUTED} [overflow-wrap:anywhere]")
                with ui.column().classes("w-full min-w-0 gap-2"):
                    ui.label("Observed SQL").classes("font-semibold")
                    if sql:
                        highlighted_sql(sql, "qs-sql-detail")
                    else:
                        ui.label("SQL text is unavailable for this execution error").classes(MUTED)
                with ui.column().classes("w-full min-w-0 gap-2"):
                    ui.label("Measured evidence").classes("font-semibold")
                    code = ui.code(evidence, language="json").classes(
                        "qs-evidence !m-0 w-full max-w-full"
                    )
                    code.copy_button.props('color=blue-2 aria-label="Copy measured evidence"')
                ui.label(status).classes(
                    "qs-divider w-full border-t pt-4 text-sm [overflow-wrap:anywhere] "
                    + ("text-amber-300" if error else "text-sky-300")
                )
                for title, items in sections:
                    with ui.column().classes("w-full min-w-0 gap-2"):
                        ui.label(title).classes("font-semibold")
                        for item in items:
                            with ui.row(wrap=False).classes("w-full gap-2"):
                                ui.label("•").classes("text-sky-300")
                                ui.label(item).classes(
                                    "min-w-0 whitespace-pre-line text-sm text-slate-300 "
                                    "[overflow-wrap:anywhere]"
                                )
            investigation_dialog.open()

        @ui.refreshable
        def scan_data(scans: list[ScanDetail] | None) -> None:
            if not scans:
                message = "Loading scans…" if scans is None else "No scans for this data source"
                empty_state("history", message)
                return
            with (
                ui.element("div").classes("w-full overflow-x-auto"),
                ui.element("table")
                .classes("qs-table w-full min-w-[625px] border-collapse text-left text-sm")
                .props('aria-label="Recent scans"'),
            ):
                with ui.element("thead").classes("text-slate-400"), ui.element("tr"):
                    for label in ("Scan ID", "Status", "Trigger", "Created"):
                        with ui.element("th").props("scope=col").classes("font-medium"):
                            ui.label(label)
                with ui.element("tbody"):
                    for scan in scans:
                        with ui.element("tr").classes("qs-divider border-t"):
                            with ui.element("td"):
                                ui.label(str(scan.scan_id)).classes(
                                    "whitespace-nowrap font-mono text-xs text-sky-200"
                                )
                            with ui.element("td"):
                                scan_badge = badge(scan.status.title(), JOB_TONES[scan.status])
                                if scan.error:
                                    scan_badge.tooltip(scan.error)
                            with ui.element("td").classes("text-slate-300"):
                                ui.label(scan.source.title())
                            with ui.element("td").classes("text-slate-300"):
                                compact_time(scan.created_at)

        @ui.refreshable
        def finding_data(findings: list[FindingSummary] | None) -> None:
            if not findings:
                message = (
                    "Loading findings…" if findings is None else "No findings for this data source"
                )
                empty_state("manage_search", message)
                return
            for finding in findings:
                with ui.column().classes(
                    "qs-finding qs-divider w-full min-w-0 gap-3 border-t px-4 py-4 sm:px-5"
                ):
                    with ui.row().classes("w-full items-start justify-between gap-3"):
                        with ui.column().classes("min-w-0 gap-1 sm:flex-1"):
                            ui.label(finding.anomaly_type.replace("_", " ").capitalize()).classes(
                                "text-xs font-medium text-sky-300"
                            )
                            ui.label(finding.summary).classes(
                                "text-base font-semibold leading-snug [overflow-wrap:anywhere]"
                            )
                        with ui.row(wrap=False).classes("gap-2"):
                            finding_badges(finding)
                    if finding.query_text:
                        highlighted_sql(
                            shorten(finding.query_text, width=160, placeholder="..."),
                            "qs-sql-preview",
                        )
                    with ui.row().classes("w-full items-center justify-between gap-2"):
                        with ui.row().classes(f"{MUTED} min-w-0 items-center gap-x-4 gap-y-1"):
                            source = (
                                source_label(finding.query_sources[0])
                                if finding.query_sources
                                else "Unknown"
                            )
                            if len(finding.query_sources) > 1:
                                source += f" (+{len(finding.query_sources) - 1} more)"
                            with ui.row(wrap=False).classes("min-w-0 items-center gap-1.5"):
                                ui.icon("person_outline").classes("text-sky-300")
                                ui.label(source).classes("min-w-0 [overflow-wrap:anywhere]")
                            with ui.row(wrap=False).classes("items-center gap-1.5"):
                                ui.icon("schedule").classes("text-sky-300")
                                ui.label("Last detected")
                                compact_time(finding.last_seen)
                        ui.button(
                            "Open investigation",
                            icon="arrow_outward",
                            color=None,
                            on_click=lambda finding_id=finding.id: show_finding(finding_id),
                        ).props("flat dense no-caps").classes("qs-inspect px-2 text-sky-300")

        with ui.column().classes("w-full min-w-0 gap-0") as dashboard_panel:
            with (
                ui.element("header").classes("qs-header w-full"),
                ui.row().classes(f"{WIDTH} min-h-[68px] items-center gap-x-7 gap-y-0"),
            ):
                with ui.row(wrap=False).classes("min-h-[64px] items-center gap-2.5"):
                    if logo_url:
                        ui.image(logo_url).classes("qs-brand-mark h-9 w-9").props(
                            'fit=contain alt=""'
                        )
                    else:
                        ui.icon("monitor_heart").classes("qs-brand-mark p-2 text-xl")
                    ui.label("QuerySentinel").classes(
                        "text-lg font-semibold tracking-tight text-slate-100"
                    )
                ui.button("Refresh", on_click=refresh_dashboard, icon="refresh", color=None).props(
                    "flat dense no-caps"
                ).classes("ml-auto px-2 text-slate-300 sm:order-last")
                with (
                    ui.tabs()
                    .props("align=left dense inline-label narrow-indicator no-caps")
                    .props("active-color=blue-3 indicator-color=blue-3")
                    .classes("h-11 w-full text-slate-400 sm:h-[68px] sm:w-auto")
                ) as tabs:
                    scans_tab = ui.tab("Scans", icon="radar")
                    findings_tab = ui.tab("Findings", icon="manage_search")
            with ui.element("main").classes(f"{WIDTH} min-w-0 pb-10 pt-6 sm:pt-9"):
                ui.label("Database monitoring").props("role=heading aria-level=1").classes(
                    "mb-5 text-3xl font-semibold leading-tight tracking-tight sm:text-[34px]"
                )
                with ui.row().classes(
                    f"{SURFACE} mb-4 items-center justify-between gap-3 px-4 py-3 sm:px-5"
                ):
                    with ui.row(wrap=False).classes(
                        "w-full min-w-0 items-center gap-3 md:max-w-[300px] md:flex-1"
                    ):
                        ui.icon("storage").classes("qs-blue rounded-lg p-2.5 text-lg")
                        target_select = (
                            ui.select([], label="Data source", on_change=change_target)
                            .props(FIELD)
                            .classes("min-w-0 flex-1")
                        )
                    with ui.row().classes("qs-actions w-full items-center gap-2 md:w-auto"):
                        scan_button = (
                            ui.button("Start scan", on_click=start_scan, icon="play_arrow")
                            .props(BUTTON)
                            .classes("min-h-10")
                        )
                        scan_button.disable()
                        workload_button = (
                            ui.button(
                                "Run synthetic workload",
                                on_click=start_workload,
                                icon="speed",
                                color=None,
                            )
                            .props(BUTTON)
                            .classes(f"{SECONDARY_BUTTON} min-h-10")
                        )
                        workload_button.disable()
                with ui.element("div").classes("mb-4 grid w-full grid-cols-1 gap-3 sm:grid-cols-3"):
                    scan_status, scan_detail = metric("Current scan", "radar", "blue")
                    finding_count, finding_detail = metric(
                        "Open findings", "manage_search", "amber"
                    )
                    workload_status, workload_detail = metric(
                        "Synthetic workload", "speed", "green"
                    )
                workload_error = (
                    ui.label()
                    .classes("mb-4 w-full text-sm text-rose-300 [overflow-wrap:anywhere]")
                    .props("role=status")
                    .set_visibility(False)
                )
                load_status = (
                    ui.label()
                    .classes("mb-4 w-full text-sm text-amber-300")
                    .props("role=status")
                    .set_visibility(False)
                )
                with ui.tab_panels(tabs, value=scans_tab, keep_alive=True, animated=False).classes(
                    "w-full min-w-0 !bg-transparent"
                ):
                    with (
                        ui.tab_panel(scans_tab).classes("!p-0"),
                        ui.column().classes(f"{SURFACE} gap-0 overflow-hidden"),
                    ):
                        with ui.row().classes(
                            "w-full items-center justify-between gap-2 px-4 py-4 sm:px-5"
                        ):
                            ui.label("Recent scans").props("role=heading aria-level=2").classes(
                                "text-lg font-semibold tracking-tight"
                            )
                            ui.label(f"Latest {SCAN_LIMIT}").classes(MUTED)
                        scan_data(None)
                    with (
                        ui.tab_panel(findings_tab).classes("!p-0"),
                        ui.column().classes(f"{SURFACE} gap-0 overflow-hidden"),
                    ):
                        with ui.row().classes(
                            "w-full items-center justify-between gap-2 px-4 py-4 sm:px-5"
                        ):
                            ui.label("Recent findings").props("role=heading aria-level=2").classes(
                                "text-lg font-semibold tracking-tight"
                            )
                            ui.label(f"Latest {FINDING_LIMIT}").classes(MUTED)
                        finding_data(None)
        dashboard_panel.set_visibility(False)
        workload_timer = ui.timer(3.0, refresh_workload, active=False, immediate=False)

        def update_overview() -> None:
            active = next(
                (
                    scan
                    for scan in recent_scans or []
                    if scan.status in (JobStatus.QUEUED, JobStatus.RUNNING)
                ),
                None,
            )
            if active:
                scan_status.set_text(active.status.title())
                scan_detail.set_text(f"{active.source.title()} scan in progress")
            elif recent_scans:
                latest = recent_scans[0]
                scan_status.set_text(latest.status.title())
                scan_detail.set_text(f"Last scan · {latest.created_at:%d %b %Y, %H:%M %Z}".rstrip())
            else:
                scan_status.set_text("—" if recent_scans is None else "No scans yet")
                scan_detail.set_text("")
            if recent_findings is None:
                finding_count.set_text("—")
                finding_detail.set_text("")
            else:
                count = sum(finding.status == FindingStatus.OPEN for finding in recent_findings)
                finding_count.set_text(str(count))
                finding_detail.set_text(f"In the latest {FINDING_LIMIT} findings")

        async def refresh_scans_and_findings() -> None:
            nonlocal recent_scans, recent_findings
            if not authenticated or selected_target is None:
                return
            target_id = selected_target
            scan_button.set_enabled(targets[target_id].enabled and not scan_pending)
            scans, findings = await asyncio.gather(
                request("scans", params={"target_id": target_id, "limit": SCAN_LIMIT}),
                request("findings", params={"target_id": target_id, "limit": FINDING_LIMIT}),
            )
            if target_id != selected_target:
                return
            unavailable = scans is None or findings is None
            load_status.set_text("Could not refresh dashboard")
            load_status.set_visibility(unavailable)
            if scans is not None:
                items = ScanPage.model_validate(scans).items
                if recent_scans != items:
                    recent_scans = items
                    scan_data.refresh(items)
            if findings is not None:
                items = FindingPage.model_validate(findings).items
                if recent_findings != items:
                    recent_findings = items
                    finding_data.refresh(items)
            update_overview()

        ui.timer(3.0, refresh_scans_and_findings)

    ui.run_with(
        app,
        mount_path=mount_path,
        title="QuerySentinel",
        dark=True,
        show_welcome_message=False,
    )
