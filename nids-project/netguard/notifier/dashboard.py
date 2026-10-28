"""Forward alerts to a standalone NetGuard dashboard server."""

from __future__ import annotations

import base64
import logging
import threading
import time
from queue import Empty, Full, Queue
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
        self._telemetry_url = f"{config.dashboard_url.rstrip('/')}/api/telemetry"
        self._telemetry_queue: Queue[dict | None] = Queue(maxsize=1)
        self._telemetry_lock = threading.Lock()
        self._telemetry_worker: threading.Thread | None = None
        self._telemetry_closed = False

    def notify(self, alert: "Alert") -> None:
        payload = alert.to_dict()
        payload["project_id"] = self._config.project_id
        try:
            response = requests.post(
                self._url, json=payload, headers=self._headers(), timeout=3.0
            )
            if response.status_code >= 400:
                logger.warning("Dashboard event delivery failed with status %s", response.status_code)
        except requests.RequestException as exc:
            logger.warning("Dashboard event delivery failed: %s", exc)

    def notify_telemetry(self, stats: dict) -> None:
        """Queue the latest app snapshot without blocking its request handler."""
        payload = {"project_id": self._config.project_id, "stats": stats}
        with self._telemetry_lock:
            if self._telemetry_closed:
                return
            if self._telemetry_worker is None or not self._telemetry_worker.is_alive():
                self._telemetry_worker = threading.Thread(
                    target=self._send_telemetry,
                    daemon=True,
                    name=f"netguard-dashboard-{self._config.project_id}",
                )
                self._telemetry_worker.start()
            try:
                self._telemetry_queue.put_nowait(payload)
            except Full:
                try:
                    self._telemetry_queue.get_nowait()
                except Empty:
                    pass
                self._telemetry_queue.put_nowait(payload)

    def _send_telemetry(self) -> None:
        headers = self._headers()
        last_sent = 0.0
        while True:
            payload = self._telemetry_queue.get()
            if payload is None:
                return

            delay = 0.5 - (time.monotonic() - last_sent)
            if delay > 0:
                time.sleep(delay)
                # Coalesce updates received while throttled to the newest snapshot.
                while True:
                    try:
                        newer = self._telemetry_queue.get_nowait()
                    except Empty:
                        break
                    if newer is None:
                        return
                    payload = newer

            try:
                response = requests.post(
                    self._telemetry_url,
                    json=payload,
                    headers=headers,
                    timeout=3.0,
                )
                if response.status_code >= 400:
                    logger.warning("Dashboard telemetry delivery failed with status %s", response.status_code)
            except requests.RequestException as exc:
                logger.warning("Dashboard telemetry delivery failed: %s", exc)
            last_sent = time.monotonic()

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._config.ingest_key:
            headers["Authorization"] = f"Bearer {self._config.ingest_key}"
        elif self._config.auth_api_key:
            headers["Authorization"] = f"Bearer {self._config.auth_api_key}"
        elif self._config.auth_username and self._config.auth_password:
            token = base64.b64encode(
                f"{self._config.auth_username}:{self._config.auth_password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"
        return headers

    def close(self) -> None:
        """Stop the best-effort telemetry worker during SDK shutdown."""
        with self._telemetry_lock:
            if self._telemetry_closed:
                return
            self._telemetry_closed = True
            worker = self._telemetry_worker
            if worker is None:
                return
            try:
                # Let the newest pending snapshot drain before stopping the worker.
                self._telemetry_queue.put(None, timeout=3.5)
            except Full:
                logger.warning("Dashboard telemetry worker did not drain before shutdown")
                return
        worker.join(timeout=3.5)
