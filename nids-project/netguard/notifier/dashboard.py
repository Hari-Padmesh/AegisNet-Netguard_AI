"""Forward alerts to a standalone NetGuard dashboard server."""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING

import requests

from netguard.notifier.base import AlertNotifier

if TYPE_CHECKING:
    from netguard.alerts import Alert
    from netguard.config import NetGuardConfig

logger = logging.getLogger(__name__)


class DashboardEventNotifier(AlertNotifier):
    """POST normalized alert events to a separate dashboard process."""

    def __init__(self, config: "NetGuardConfig"):
        self._config = config
        self._url = f"{config.dashboard_url.rstrip('/')}/api/events"

    def notify(self, alert: "Alert") -> None:
        headers = {"Content-Type": "application/json"}
        if self._config.auth_api_key:
            headers["Authorization"] = f"Bearer {self._config.auth_api_key}"
        elif self._config.auth_username and self._config.auth_password:
            token = base64.b64encode(
                f"{self._config.auth_username}:{self._config.auth_password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"

        payload = alert.to_dict()
        payload["project_id"] = self._config.project_id
        try:
            requests.post(self._url, json=payload, headers=headers, timeout=3.0)
        except requests.RequestException as exc:
            logger.warning("Dashboard event delivery failed: %s", exc)