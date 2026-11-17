from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class JobSource(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(StrEnum):
    EXECUTION_ERROR = "execution_error"
    NEW_EXPENSIVE = "new_expensive_query"
    LATENCY_REGRESSION = "latency_regression"
    WORKLOAD_REGRESSION = "workload_cost_regression"
    HIGH_TEMP_IO = "high_temporary_block_io"
    BLOCK_READ_REGRESSION = "block_read_regression"


class InvestigationStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    FAILED_OR_SKIPPED = "failed_or_skipped"


class InvestigationResult(BaseModel):
    target_id: str
    scan_id: UUID
    query_fingerprint: str
    anomaly_type: AnomalyType
    severity: Severity
    evidence: dict[str, Any]
    suspected_causes: list[str] = Field(default_factory=list, max_length=10)
    hypotheses: list[str] = Field(default_factory=list, max_length=10)
    remediation: list[str] = Field(default_factory=list, max_length=10)
    verification_steps: list[str] = Field(default_factory=list, max_length=10)
    confidence: float = Field(ge=0, le=1)
    status: InvestigationStatus


class TargetResponse(BaseModel):
    id: str
    engine: str
    enabled: bool
    schedule: str
    synthetic_workload_enabled: bool = False


class ScanRequest(BaseModel):
    target_id: str


class ScanResponse(BaseModel):
    scan_id: UUID
    target_id: str
    status: JobStatus


class SyntheticWorkloadRequest(BaseModel):
    target_id: str
    queries: int = Field(default=20, ge=1, le=50)
    rounds: int = Field(default=10, ge=1, le=100)
    fresh: bool = False


class SyntheticWorkloadResponse(BaseModel):
    job_id: UUID
    target_id: str
    status: JobStatus
    query_count: int
    rounds: int
    fresh: bool
    generated: bool
    succeeded: int
    failed: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None


class ScanDetail(ScanResponse):
    source: JobSource
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    attempts: int
    error: str | None


class QuerySource(BaseModel):
    username: str | None = None
    client: str | None = None
    last_seen: datetime
    occurrences: int = Field(ge=1)
    observation_kind: Literal["duration_log"] | None = None


class FindingSummary(BaseModel):
    id: UUID
    target_id: str
    query_fingerprint: str
    query_text: str
    anomaly_type: AnomalyType
    severity: Severity
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    resolution_reason: str | None = None
    summary: str
    query_sources: list[QuerySource] = Field(default_factory=list)


class FindingDetail(FindingSummary):
    current_evidence: dict[str, Any]
    observations: int
    latest_investigation: InvestigationResult | None = None
    investigation_status: InvestigationStatus | None = None
    investigation_error: str | None = None
    investigation_model: str | None = None
    investigation_created_at: datetime | None = None
    investigation_input_tokens: int | None = None
    investigation_output_tokens: int | None = None


class ScanPage(BaseModel):
    items: list[ScanDetail]
    total: int
    limit: int
    offset: int


class SyntheticWorkloadPage(BaseModel):
    items: list[SyntheticWorkloadResponse]
    total: int
    limit: int
    offset: int


class FindingPage(BaseModel):
    items: list[FindingSummary]
    total: int
    limit: int
    offset: int
