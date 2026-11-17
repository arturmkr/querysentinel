from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from querysentinel.config import Settings
from querysentinel.jobs import claim_job, enqueue_job
from querysentinel.models import Finding, NotificationDelivery, ScanJob
from querysentinel.notifier import Notifier, deliver_notification
from querysentinel.schemas import (
    AnomalyType,
    InvestigationResult,
    InvestigationStatus,
    JobSource,
    JobStatus,
    Severity,
)


class RecordingNotifier(Notifier):
    channel = "test"

    def __init__(self):
        self.payloads = []

    def send(self, payload):
        self.payloads.append(payload)


def test_job_claim_is_persistent_and_leased(session) -> None:
    queued = enqueue_job(session, "airlines", JobSource.MANUAL)
    claimed = claim_job(session, lease_seconds=30, max_attempts=3)
    assert claimed.id == queued.id
    assert claimed.status == JobStatus.RUNNING
    assert claimed.lease_expires_at is not None


def test_notification_attempt_is_persisted(session) -> None:
    job = ScanJob(target_id="airlines", source=JobSource.MANUAL)
    finding = Finding(
        target_id="airlines",
        query_fingerprint="f" * 64,
        query_text="SELECT 1",
        anomaly_type=AnomalyType.LATENCY_REGRESSION,
        severity=Severity.HIGH,
        summary="regressed",
        current_evidence={"ratio": 4},
    )
    session.add_all([job, finding])
    session.commit()
    notifier = RecordingNotifier()
    deliver_notification(session, job, finding, "new", notifier)
    assert len(notifier.payloads) == 1
    assert session.query(NotificationDelivery).one().status == "delivered"


def test_investigation_output_validation() -> None:
    valid = {
        "target_id": "airlines",
        "scan_id": str(uuid4()),
        "query_fingerprint": "f" * 64,
        "anomaly_type": "latency_regression",
        "severity": "high",
        "evidence": {"ratio": 4},
        "confidence": 0.8,
        "status": "success",
    }
    assert InvestigationResult.model_validate(valid).status == InvestigationStatus.SUCCESS
    with pytest.raises(ValidationError):
        InvestigationResult.model_validate(valid | {"confidence": 2})


def test_model_credentials_follow_the_selected_provider() -> None:
    openai = Settings(_env_file=None, ai_model="openai:gpt-test", openai_api_key="openai-key")
    anthropic = Settings(
        _env_file=None,
        ai_model="anthropic:claude-test",
        openai_api_key="",
        anthropic_api_key="anthropic-key",
    )
    google = Settings(
        _env_file=None,
        ai_model="google:gemini-test",
        openai_api_key="",
        google_api_key="google-key",
    )
    missing = Settings(_env_file=None, ai_model="google:gemini-test", google_api_key="")

    assert openai.model_credentials_configured()
    assert anthropic.model_credentials_configured()
    assert google.model_credentials_configured()
    assert not missing.model_credentials_configured()
