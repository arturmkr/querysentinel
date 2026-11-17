from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from querysentinel import application
from querysentinel.config import Settings, get_settings, load_project_config
from querysentinel.db import session_dependency
from querysentinel.jobs import ActiveScanError
from querysentinel.logging import configure_logging
from querysentinel.mcp_server import create_mcp_http_app
from querysentinel.schemas import (
    FindingDetail,
    FindingPage,
    FindingStatus,
    JobSource,
    JobStatus,
    ScanDetail,
    ScanPage,
    ScanRequest,
    ScanResponse,
    Severity,
    SyntheticWorkloadPage,
    SyntheticWorkloadRequest,
    SyntheticWorkloadResponse,
    TargetResponse,
)

security = HTTPBearer(auto_error=False)


def require_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(security)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    if not settings.api_token:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    if credentials is None or not secrets.compare_digest(
        credentials.credentials, settings.api_token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    mcp_server, mcp_http_app = create_mcp_http_app(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with mcp_server.session_manager.run():
            yield

    app = FastAPI(
        title="QuerySentinel API",
        version="0.1.0",
        description="Asynchronous PostgreSQL performance scan and findings API",
        lifespan=lifespan,
    )
    app.mount("/mcp", mcp_http_app, name="mcp")

    @app.exception_handler(application.TargetNotFoundError)
    async def target_not_found(_: Request, __: application.TargetNotFoundError):
        return JSONResponse({"detail": "target not found"}, status_code=404)

    @app.exception_handler(application.TargetDisabledError)
    async def target_disabled(_: Request, __: application.TargetDisabledError):
        return JSONResponse({"detail": "target is disabled"}, status_code=409)

    @app.exception_handler(application.ScanNotFoundError)
    async def scan_not_found(_: Request, __: application.ScanNotFoundError):
        return JSONResponse({"detail": "scan not found"}, status_code=404)

    @app.exception_handler(application.FindingNotFoundError)
    async def finding_not_found(_: Request, __: application.FindingNotFoundError):
        return JSONResponse({"detail": "finding not found"}, status_code=404)

    @app.exception_handler(application.SyntheticWorkloadNotFoundError)
    async def workload_not_found(_: Request, __: application.SyntheticWorkloadNotFoundError):
        return JSONResponse({"detail": "synthetic workload not found"}, status_code=404)

    @app.exception_handler(application.SyntheticWorkloadDisabledError)
    async def workload_disabled(_: Request, __: application.SyntheticWorkloadDisabledError):
        return JSONResponse({"detail": "synthetic workload is disabled"}, status_code=409)

    @app.exception_handler(application.WorkloadConfigurationError)
    async def workload_unavailable(_: Request, exc: application.WorkloadConfigurationError):
        return JSONResponse({"detail": str(exc)}, status_code=503)

    @app.exception_handler(ActiveScanError)
    async def active_scan(_: Request, exc: ActiveScanError):
        return JSONResponse(
            {
                "detail": {
                    "message": "target already has an active scan",
                    "scan_id": str(exc.job.id),
                }
            },
            status_code=409,
        )

    @app.get("/health", tags=["system"])
    def health(session: Session = Depends(session_dependency)):
        try:
            session.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(status_code=503, detail="state database unavailable") from None
        return {"status": "ok"}

    protected = [Depends(require_token)]

    @app.get("/api/v1/targets", response_model=list[TargetResponse], dependencies=protected)
    def list_targets():
        return application.list_targets(load_project_config())

    @app.get("/api/v1/targets/{target_id}", response_model=TargetResponse, dependencies=protected)
    def get_target(target_id: str):
        return application.get_target(load_project_config(), target_id)

    @app.get(
        "/api/v1/scans",
        response_model=ScanPage,
        dependencies=protected,
    )
    def list_scans(
        session: Session = Depends(session_dependency),
        target_id: str | None = None,
        job_status: JobStatus | None = Query(alias="status", default=None),
        source: JobSource | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        return application.list_scans(
            session,
            load_project_config(),
            target_id=target_id,
            status=job_status,
            source=source,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    @app.post(
        "/api/v1/scans",
        response_model=ScanResponse,
        status_code=202,
        dependencies=protected,
    )
    def start_scan(request: ScanRequest, session: Session = Depends(session_dependency)):
        return application.start_scan(session, load_project_config(), request.target_id)

    @app.post(
        "/api/v1/synthetic-workloads",
        response_model=SyntheticWorkloadResponse,
        status_code=202,
        dependencies=protected,
    )
    def start_synthetic_workload(
        request: SyntheticWorkloadRequest,
        session: Session = Depends(session_dependency),
    ):
        return application.start_synthetic_workload(session, load_project_config(), request)

    @app.get(
        "/api/v1/synthetic-workloads", response_model=SyntheticWorkloadPage, dependencies=protected
    )
    def list_synthetic_workloads(
        session: Session = Depends(session_dependency),
        target_id: str | None = None,
        job_status: JobStatus | None = Query(alias="status", default=None),
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        return application.list_synthetic_workloads(
            session,
            load_project_config(),
            target_id=target_id,
            status=job_status,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    @app.get(
        "/api/v1/synthetic-workloads/{job_id}",
        response_model=SyntheticWorkloadResponse,
        dependencies=protected,
    )
    def get_synthetic_workload(job_id: UUID, session: Session = Depends(session_dependency)):
        return application.get_synthetic_workload(session, job_id)

    @app.get("/api/v1/scans/{scan_id}", response_model=ScanDetail, dependencies=protected)
    def get_scan(scan_id: UUID, session: Session = Depends(session_dependency)):
        return application.get_scan(session, scan_id)

    @app.get("/api/v1/findings", response_model=FindingPage, dependencies=protected)
    def list_findings(
        session: Session = Depends(session_dependency),
        target_id: str | None = None,
        scan_id: UUID | None = None,
        severity: Severity | None = None,
        finding_status: FindingStatus | None = Query(alias="status", default=None),
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ) -> FindingPage:
        return application.list_findings(
            session,
            load_project_config(),
            target_id=target_id,
            scan_id=scan_id,
            severity=severity,
            status=finding_status,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    @app.get("/api/v1/findings/{finding_id}", response_model=FindingDetail, dependencies=protected)
    def finding_detail(finding_id: UUID, session: Session = Depends(session_dependency)):
        return application.get_finding(session, finding_id)

    from querysentinel.ui import install_ui

    install_ui(app)
    return app


app = create_app()
