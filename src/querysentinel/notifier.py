from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from sqlalchemy.orm import Session

from querysentinel.models import NotificationDelivery, ScanJob

logger = structlog.get_logger()


class Notifier(ABC):
    channel: str

    @abstractmethod
    def send(self, payload: dict[str, Any]) -> None: ...


class ConsoleNotifier(Notifier):
    channel = "console"

    def send(self, payload: dict[str, Any]) -> None:
        log_fields = payload.copy()
        log_fields["finding_event"] = log_fields.pop("event")
        logger.info("finding_notification", **log_fields)


class WebhookNotifier(Notifier):
    channel = "webhook"

    def __init__(self, url: str, timeout_seconds: float = 5) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds

    def send(self, payload: dict[str, Any]) -> None:
        response = httpx.post(self.url, json=payload, timeout=self.timeout_seconds)
        response.raise_for_status()


def notification_payload(finding, event: str) -> dict[str, Any]:
    return {
        "event": event,
        "finding_id": str(finding.id),
        "target_id": finding.target_id,
        "query_fingerprint": finding.query_fingerprint,
        "query_text": finding.query_text,
        "anomaly_type": finding.anomaly_type,
        "severity": finding.severity,
        "status": finding.status,
        "summary": finding.summary,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "resolution_reason": finding.resolution_reason,
        "evidence": finding.current_evidence,
    }


def deliver_notification(
    session: Session,
    job: ScanJob,
    finding,
    event: str,
    notifier: Notifier,
    max_attempts: int = 3,
) -> None:
    payload = notification_payload(finding, event)
    for attempt in range(1, max_attempts + 1):
        delivery = NotificationDelivery(
            finding_id=finding.id,
            scan_id=job.id,
            event=event,
            channel=notifier.channel,
            attempt=attempt,
            status="pending",
        )
        session.add(delivery)
        session.flush()
        try:
            notifier.send(payload)
        except Exception as exc:  # delivery failures must not fail the scan
            delivery.status = "failed"
            delivery.error = str(exc)[:2000]
            session.commit()
            if attempt < max_attempts:
                time.sleep(0.2 * (2 ** (attempt - 1)))
        else:
            delivery.status = "delivered"
            delivery.delivered_at = datetime.now(UTC)
            session.commit()
            return
