"""
netguard/notifier/email.py
--------------------------
SMTP email notifications (Gmail-compatible) for instant threat alerts.
Weekly digest delivery is implemented in Phase 3.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import TYPE_CHECKING, Optional

from netguard.config import NetGuardConfig
from netguard.notifier.base import AlertNotifier

if TYPE_CHECKING:
    from netguard.alerts import Alert

logger = logging.getLogger(__name__)


class EmailNotifier(AlertNotifier):
    """Send instant email alerts when threats are detected."""

    def __init__(self, config: NetGuardConfig):
        self._config = config

    def notify(self, alert: "Alert") -> None:
        if not self._config.smtp_configured:
            logger.debug("EmailNotifier skipped: SMTP not fully configured.")
            return

        subject = f"[NetGuard:{self._config.project_id}] {alert.severity.value} — {alert.label}"
        body = (
            f"NetGuard detected a potential threat in project '{self._config.project_id}'.\n\n"
            f"Severity   : {alert.severity.value}\n"
            f"Attack type: {alert.label}\n"
            f"Confidence : {alert.confidence:.1%}\n"
            f"Time       : {alert.timestamp}\n"
            f"Details    : {alert.flow_summary}\n"
        )
        self._send(subject, body)

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
