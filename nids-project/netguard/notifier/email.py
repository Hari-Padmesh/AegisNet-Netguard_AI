"""
netguard/notifier/email.py
--------------------------
SMTP email notifications (Gmail-compatible) for instant threat alerts.
Weekly digest delivery is implemented in Phase 3.
"""

from __future__ import annotations

import logging
import smtplib
import threading
import time
from collections.abc import Iterable
from email.message import EmailMessage
from typing import TYPE_CHECKING, Optional

from netguard.config import NetGuardConfig
from netguard.notifier.base import AlertNotifier

if TYPE_CHECKING:
    from netguard.alerts import Alert

logger = logging.getLogger(__name__)


class EmailNotifier(AlertNotifier):
    """Send instant email alerts when threats are detected.

    Parameters
    ----------
    config : NetGuardConfig
        SDK configuration (SMTP credentials, recipient, etc.).
    cooldown_seconds : float
        Minimum seconds between emails for the same attack label.
        Prevents email floods during DoS bursts. Default: 60 s.
        Set to 0 to disable cooldown (not recommended for production).
    """

    def __init__(self, config: NetGuardConfig, cooldown_seconds: float = 60.0):
        self._config = config
        self._cooldown = cooldown_seconds
        # {label: last_sent_timestamp}
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()

    def notify(self, alert: "Alert") -> None:
        if not self._config.smtp_configured:
            logger.debug("EmailNotifier skipped: SMTP not fully configured.")
            return

        # Cooldown check — skip if same label was emailed recently
        if self._cooldown > 0:
            now = time.monotonic()
            with self._lock:
                last = self._last_sent.get(alert.label, 0.0)
                if now - last < self._cooldown:
                    logger.debug(
                        "EmailNotifier cooldown active for %s (%.0fs remaining).",
                        alert.label,
                        self._cooldown - (now - last),
                    )
                    return
                self._last_sent[alert.label] = now

        subject = f"[NetGuard:{self._config.project_id}] {alert.severity.value} — {alert.label}"
        body = (
            f"NetGuard detected a potential threat in project '{self._config.project_id}'.\n\n"
            f"Severity   : {alert.severity.value}\n"
            f"Attack type: {alert.label}\n"
            f"Confidence : {alert.confidence:.1%}\n"
            f"Time       : {alert.timestamp}\n"
            f"Details    : {alert.flow_summary}\n"
        )
        # Send in a daemon thread so SMTP latency never blocks the HTTP response
        t = threading.Thread(target=self._send, args=(subject, body), daemon=True)
        t.start()

    def send_digest(self, alerts: Iterable["Alert"]) -> bool:
        """Send a summary email and return whether SMTP delivery was attempted."""
        if not self._config.smtp_configured:
            logger.debug("Email digest skipped: SMTP not fully configured.")
            return False

        alert_list = list(alerts)
        counts = {}
        for alert in alert_list:
            counts[alert.label] = counts.get(alert.label, 0) + 1
        breakdown = "\n".join(f"- {label}: {count}" for label, count in sorted(counts.items()))
        body = (
            f"NetGuard weekly digest for project '{self._config.project_id}'.\n\n"
            f"Total alerts: {len(alert_list)}\n"
            f"Attack breakdown:\n{breakdown or '- No alerts'}\n"
        )
        self._send(
            f"[NetGuard:{self._config.project_id}] Weekly security digest",
            body,
        )
        return True

    def _send(self, subject: str, body: str, to_addr: Optional[str] = None) -> None:
        cfg = self._config
        recipient = to_addr or cfg.alert_email
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg.smtp_from or cfg.smtp_user
        msg["To"] = recipient
        msg.set_content(body)

        try:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as server:
                if cfg.smtp_use_tls:
                    server.starttls()
                server.login(cfg.smtp_user, cfg.smtp_password)
                server.send_message(msg)
        except Exception as exc:
            logger.warning("EmailNotifier failed to send: %s", exc)
