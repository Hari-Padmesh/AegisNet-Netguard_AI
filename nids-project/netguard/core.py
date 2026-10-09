"""
netguard/core.py
----------------
Main embeddable NetGuard SDK entry point.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import List, Optional

from netguard.aggregator import HttpFlow, HttpFlowAggregator
from netguard.alerts import Alert, AlertManager, Severity
from netguard.config import DashboardMode, NetGuardConfig
from netguard.detection import DetectionEngine, PredictionResult, get_default_model_dir
from netguard.notifier.email import EmailNotifier
from netguard.notifier.dashboard import DashboardEventNotifier
from netguard.notifier.webhook import WebhookNotifier
from netguard.rules import ApplicationRuleEngine

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
        if isinstance(self.config.dashboard_mode, str):
            self.config.dashboard_mode = DashboardMode(self.config.dashboard_mode.lower())
        self.config.validate_auth()

        model_dir = self.config.model_dir
        if model_dir == "models" and not os.path.exists(os.path.join(model_dir, "best_model.pkl")):
            model_dir = get_default_model_dir()
        self._engine = DetectionEngine(model_dir=model_dir).load()
        self._aggregator = HttpFlowAggregator(window_seconds=self.config.flow_window_seconds)
        self._rules = ApplicationRuleEngine(window_seconds=self.config.flow_window_seconds)
        self._alert_manager = self._build_alert_manager()
        self._lock = threading.Lock()
        self._request_count = 0
        self._flow_count = 0
        self._prediction_count = 0
        self._attack_count = 0
        self._blocked_ips: dict[str, float] = {}

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
        if self.config.webhook_url:
            mgr.register_notifier(WebhookNotifier(self.config.webhook_url, min_severity=min_severity))
        if self.config.slack_webhook_url:
            mgr.register_notifier(WebhookNotifier(self.config.slack_webhook_url, service="slack", min_severity=min_severity))
        if self.config.dashboard_mode in (DashboardMode.SEPARATE, DashboardMode.BOTH):
            mgr.register_notifier(DashboardEventNotifier(self.config))

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

    def block_ip(self, client_ip: str, duration_seconds: float = 300.0) -> None:
        """Block an application client IP for a bounded period."""
        with self._lock:
            self._blocked_ips[client_ip] = time.time() + duration_seconds

    def unblock_ip(self, client_ip: str) -> None:
        """Remove an application client IP block."""
        with self._lock:
            self._blocked_ips.pop(client_ip, None)

    def is_ip_blocked(self, client_ip: str) -> bool:
        """Return whether a client IP is currently blocked."""
        with self._lock:
            expires_at = self._blocked_ips.get(client_ip)
            if expires_at is None:
                return False
            if expires_at <= time.time():
                del self._blocked_ips[client_ip]
                return False
            return True

    def get_blocked_ips(self) -> dict[str, float]:
        """Return active blocked IPs and their remaining seconds."""
        now = time.time()
        with self._lock:
            active = {}
            for client_ip, expires_at in list(self._blocked_ips.items()):
                remaining = expires_at - now
                if remaining > 0:
                    active[client_ip] = round(remaining, 1)
                else:
                    del self._blocked_ips[client_ip]
            return active

    def process_request(
        self,
        client_ip: str,
        req_bytes: float,
        resp_bytes: float,
        dest_port: int = 80,
        path: str = "",
        method: str = "GET",
        query_string: str = "",
        status_code: int = 200,
    ) -> List[PredictionResult]:
        """
        Record one HTTP exchange and classify any completed client flows.

        Returns prediction results for flows scored during this call.
        """
        with self._lock:
            self._request_count += 1
            results: List[PredictionResult] = []

            rule_match = self._rules.evaluate(
                client_ip=client_ip,
                path=path,
                query_string=query_string,
                status_code=status_code,
            )
            if rule_match:
                rule_result = self._rule_result(
                    rule_match.label,
                    rule_match.confidence,
                    rule_match.rule_id,
                    client_ip,
                    path,
                )
                self._prediction_count += 1
                alert = self._alert_manager.trigger(rule_result)
                if alert is not None and alert.severity != Severity.INFO:
                    self._attack_count += 1
                results.append(rule_result)

            completed = self._aggregator.add_request(
                client_ip=client_ip,
                req_bytes=req_bytes,
                resp_bytes=resp_bytes,
                dest_port=dest_port,
                path=path,
            )
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
        self._flow_count += 1
        feature_dict = flow.to_feature_vector()
        summary = f"{flow.summary()} [{self.config.project_id}]"
        result = self._engine.predict(feature_dict, flow_summary=summary)
        self._prediction_count += 1

        if result.is_attack and result.confidence < self.config.attack_confidence_threshold:
            return result

        alert = self._alert_manager.trigger(result)
        if alert is not None and alert.severity != Severity.INFO:
            self._attack_count += 1

        return result

    def _rule_result(
        self,
        label: str,
        confidence: float,
        rule_id: str,
        client_ip: str,
        path: str,
    ) -> PredictionResult:
        return PredictionResult(
            label=label,
            label_index=-1,
            confidence=confidence,
            probabilities={"BENIGN": 1.0 - confidence, label: confidence},
            is_attack=True,
            flow_summary=f"HTTP {client_ip} {path} | rule={rule_id}",
            detection_source="rule",
        )

    def stats(self) -> dict:
        """Return runtime statistics for dashboards."""
        alert_stats = self._alert_manager.stats()
        total_attacks = self._attack_count
        threat_level = "NOMINAL" if total_attacks == 0 else "ELEVATED"
        if total_attacks >= 5:
            threat_level = "CRITICAL"
        return {
            "project_id": self.config.project_id,
            "requests": self._request_count,
            "total_requests": self._request_count,
            "flows_scored": self._flow_count,
            "predictions": self._prediction_count,
            "attacks": total_attacks,
            "total_attacks": total_attacks,
            "benign_requests": max(0, self._request_count - total_attacks),
            "active_flows": self._aggregator.active_count,
            "blocked_ips_count": len(self.get_blocked_ips()),
            "alerts": alert_stats,
            "attacks_by_label": alert_stats["by_label"],
            "attacks_by_severity": alert_stats["by_severity"],
            "recent_events": [alert.to_dict() for alert in self.recent_alerts(30)],
            "top_clients": [],
            "threat_level": threat_level,
            "threat_color": {
                "NOMINAL": "emerald",
                "ELEVATED": "amber",
                "CRITICAL": "crimson",
            }[threat_level],
            "dashboard_mode": self.config.dashboard_mode.value,
        }

    def recent_alerts(self, limit: int = 50) -> List[Alert]:
        history = self._alert_manager.history
        return history[-limit:]
