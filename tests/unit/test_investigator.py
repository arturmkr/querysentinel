from uuid import uuid4

from pydantic_ai.models.test import TestModel

from querysentinel.config import Settings
from querysentinel.detector import Anomaly
from querysentinel.investigator import build_agent, extract_table_names, investigate
from querysentinel.models import ScanJob
from querysentinel.schemas import (
    AnomalyType,
    InvestigationResult,
    InvestigationStatus,
    JobSource,
    Severity,
)


def test_extract_table_names_limits_tools_to_observed_tables() -> None:
    query = "SELECT * FROM bookings.flights f JOIN bookings.routes r ON true"
    assert extract_table_names(query) == ["flights", "routes"]


def test_investigation_uses_pydantic_test_model_without_paid_call() -> None:
    job = ScanJob(id=uuid4(), target_id="airlines", source=JobSource.MANUAL)
    anomaly = Anomaly(
        fingerprint="f" * 64,
        query_text="SELECT * FROM bookings.flights",
        anomaly_type=AnomalyType.LATENCY_REGRESSION,
        severity=Severity.HIGH,
        summary="regressed",
        evidence={"ratio": 4},
    )
    output = InvestigationResult(
        target_id=job.target_id,
        scan_id=job.id,
        query_fingerprint=anomaly.fingerprint,
        anomaly_type=anomaly.anomaly_type,
        severity=anomaly.severity,
        evidence=anomaly.evidence,
        confidence=0.8,
        status=InvestigationStatus.SUCCESS,
    )

    settings = Settings(
        _env_file=None,
        api_token="test",
        openai_api_key="test-key",
        ai_model="test",
        llm_timeout_seconds=3,
        llm_max_tool_calls=2,
    )
    agent = build_agent(settings)
    model = TestModel(call_tools=[], custom_output_args=output.model_dump(mode="json"))
    with agent.override(model=model):
        result, input_tokens, output_tokens = investigate(
            settings, object(), job, anomaly, agent=agent
        )
    assert result.status == InvestigationStatus.SUCCESS
    assert input_tokens is not None and input_tokens > 0
    assert output_tokens is not None and output_tokens > 0
