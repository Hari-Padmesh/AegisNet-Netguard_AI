"""Resend HTTPS API email notifications."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING

import requests

from netguard.config import NetGuardConfig
from netguard.notifier.base import AlertNotifier

if TYPE_CHECKING:
    from netguard.alerts import Alert

logger = logging.getLogger(__name__)


class ResendEmailNotifier(AlertNotifier):
    """Send immediate alerts and digests through Resend's HTTPS API.

    This is useful on hosts that block outbound SMTP but allow HTTPS requests.
    Configure ``NETGUARD_EMAIL_PROVIDER=resend``, an API key, sender, and
    recipient. The default Resend test sender can only be used for testing;
    production senders should use a verified domain.
    """

    API_URL = "https://api.resend.com/emails"

    def __init__(self, config: NetGuardConfig, cooldown_seconds: float = 60.0):
        self._config = config
        self._cooldown = max(0.0, cooldown_seconds)
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()

    def notify(self, alert: "Alert") -> None:
        if not self._config.resend_configured:
            logger.debug("ResendEmailNotifier skipped: Resend is not fully configured.")
            return

        if self._cooldown:
            now = time.monotonic()
            with self._lock:
                last = self._last_sent.get(alert.label, 0.0)
                if now - last < self._cooldown:
                    logger.debug("Resend email cooldown active for %s.", alert.label)
                    return
                self._last_sent[alert.label] = now

        subject, body = self._alert_message(alert)
        threading.Thread(
            target=self._send,
            args=(subject, body),
            daemon=True,
            name=f"netguard-resend-{alert.label}",
        ).start()

    def send_digest(self, alerts: Iterable["Alert"]) -> bool:
        """Send the current alert history as a digest through the API."""
        if not self._config.resend_configured:
            logger.debug("Resend digest skipped: Resend is not fully configured.")
            return False

        alert_list = list(alerts)
        counts: dict[str, int] = {}
        for alert in alert_list:
            counts[alert.label] = counts.get(alert.label, 0) + 1
        breakdown = "\n".join(
            f"- {label}: {count}" for label, count in sorted(counts.items())
        ) or "- No alerts"
        body = (
            f"NetGuard weekly digest for project '{self._config.project_id}'.\n\n"
            f"Total alerts: {len(alert_list)}\n"
            f"Attack breakdown:\n{breakdown}\n"
        )
        return self._send(
            f"[NetGuard:{self._config.project_id}] Weekly security digest",
            body,
        )

    def _alert_message(self, alert: "Alert") -> tuple[str, str]:
        subject = f"[NetGuard:{self._config.project_id}] {alert.severity.value} - {alert.label}"
        body = (
            f"NetGuard detected a potential threat in project '{self._config.project_id}'.\n\n"
            f"Severity   : {alert.severity.value}\n"
            f"Attack type: {alert.label}\n"
            f"Confidence : {alert.confidence:.1%}\n"
            f"Time       : {alert.timestamp}\n"
            f"Details    : {alert.flow_summary}\n"
        )
        return subject, body

    def _send(self, subject: str, body: str) -> bool:
        config = self._config
        try:
            response = requests.post(
                self.API_URL,
                headers={"Authorization": f"Bearer {config.resend_api_key}"},
                json={
                    "from": config.resend_from,
                    "to": [config.alert_email],
                    "subject": subject,
                    "text": body,
                },
                timeout=15.0,
            )
            if response.status_code >= 400:
                logger.warning(
                    "Resend API email failed with status %s: %s",
                    response.status_code,
                    response.text[:1000],
                )
                return False
            logger.info("Resend API accepted email: %s", subject)
            return True
        except requests.RequestException as exc:
            logger.warning("Resend API email request failed: %s", exc)
            return False
