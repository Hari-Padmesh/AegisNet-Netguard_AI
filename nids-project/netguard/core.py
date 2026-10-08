"""
netguard/core.py
----------------
Main embeddable NetGuard SDK entry point.
"""

from __future__ import annotations

import logging
import threading
from typing import List, Optional

from netguard.aggregator import HttpFlow, HttpFlowAggregator
from netguard.alerts import Alert, AlertManager, Severity
from netguard.config import DashboardMode, NetGuardConfig
from netguard.detection import DetectionEngine, PredictionResult
from netguard.notifier.email import EmailNotifier

logger = logging.getLogger(__name__)


class NetGuard:
    """
    Embeddable network intrusion detection for web applications.

    Parameters
    ----------
    config : NetGuardConfig, optional
        Full configuration object. If omitted, built from kwargs / env vars.
    **kwargs
        Passed to NetGuardConfig.from_env() when config is not provided.

    Example
    -------
    guard = NetGuard(
        project_id="my-app",
        auth_username="admin",
        auth_password="secret",
        alert_email="owner@gmail.com",
    )
    """

    def __init__(self, config: Optional[NetGuardConfig] = None, **kwargs):
        self.config = config or NetGuardConfig.from_env(**kwargs)
        self.config.validate_auth()

        self._engine = DetectionEngine(model_dir=self.config.model_dir).load()
        self._aggregator = HttpFlowAggregator(window_seconds=self.config.flow_window_seconds)
        self._alert_manager = self._build_alert_manager()
        self._lock = threading.Lock()
        self._request_count = 0
        self._attack_count = 0

    def _build_alert_manager(self) -> AlertManager:
        try:
            min_severity = Severity[self.config.min_alert_severity.upper()]
        except KeyError:
            min_severity = Severity.LOW

        mgr = AlertManager(
            log_file=self.config.log_file,
            min_severity=min_severity,
            show_benign=False,
            console_alerts=self.config.console_alerts,
        )

        if self.config.smtp_configured:
            mgr.register_notifier(EmailNotifier(self.config))

        return mgr

    @property
    def engine(self) -> DetectionEngine:
        return self._engine

    @property
    def alert_manager(self) -> AlertManager:
        return self._alert_manager

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def attack_count(self) -> int:
        return self._attack_count

    def register_notifier(self, notifier) -> None:
        """Register an additional alert delivery channel."""
        self._alert_manager.register_notifier(notifier)

    def on_alert(self, callback) -> None:
        """Register a callback invoked for each dispatched alert."""
        self._alert_manager.register_callback(callback)

    def process_request(
        self,
        client_ip: str,
        req_bytes: float,
        resp_bytes: float,
        dest_port: int = 80,
        path: str = "",
        method: str = "GET",
    ) -> List[PredictionResult]:
        """
        Record one HTTP exchange and classify any completed client flows.

        Returns prediction results for flows scored during this call.
        """
        with self._lock:
            self._request_count += 1
            completed = self._aggregator.add_request(
                client_ip=client_ip,
                req_bytes=req_bytes,
                resp_bytes=resp_bytes,
                dest_port=dest_port,
                path=path,
            )
            results: List[PredictionResult] = []
            for flow in completed:
                result = self._score_flow(flow)
                if result:
                    results.append(result)
            return results

    def flush_idle_flows(self) -> List[PredictionResult]:
        """Score and return results for all idle flows."""
        with self._lock:
            flows = self._aggregator.collect_idle_flows()
            results: List[PredictionResult] = []
            for flow in flows:
                result = self._score_flow(flow)
                if result:
                    results.append(result)
            return results

    def shutdown(self) -> List[PredictionResult]:
        """Flush remaining flows on application shutdown."""
        with self._lock:
            flows = self._aggregator.flush_all()
            results: List[PredictionResult] = []
            for flow in flows:
                result = self._score_flow(flow)
                if result:
                    results.append(result)
            return results

    def _score_flow(self, flow: HttpFlow) -> Optional[PredictionResult]:
        feature_dict = flow.to_feature_vector()
        summary = f"{flow.summary()} [{self.config.project_id}]"
        result = self._engine.predict(feature_dict, flow_summary=summary)

        if result.is_attack and result.confidence < self.config.attack_confidence_threshold:
            return result

        alert = self._alert_manager.trigger(result)
        if alert is not None and alert.severity != Severity.INFO:
            self._attack_count += 1

        return result

    def stats(self) -> dict:
        """Return runtime statistics for dashboards."""
        alert_stats = self._alert_manager.stats()
        return {
            "project_id": self.config.project_id,
            "requests": self._request_count,
            "attacks": self._attack_count,
            "active_flows": self._aggregator.active_count,
            "alerts": alert_stats,
            "dashboard_mode": self.config.dashboard_mode.value,
        }

    def recent_alerts(self, limit: int = 50) -> List[Alert]:
        history = self._alert_manager.history
        return history[-limit:]
