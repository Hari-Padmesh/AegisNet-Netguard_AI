"""
NetGuard AI — Network Intrusion Detection System
=================================================
A machine-learning based NIDS with real-time capture,
PCAP analysis, threat alerting, and a rich TUI dashboard.
"""

__version__ = "0.1.0"
__author__ = "NetGuard AI"

from netguard.detection import DetectionEngine, PredictionResult
from netguard.alerts import AlertManager, Alert, Severity
from netguard.integrations.fastapi import NetGuardMiddleware, NetGuard
from netguard.notifier.webhook import WebhookNotifier
from netguard.notifier.email_notifier import EmailNotifier

__all__ = [
    "NetGuard",
    "NetGuardMiddleware",
    "DetectionEngine",
    "PredictionResult",
    "AlertManager",
    "Alert",
    "Severity",
    "WebhookNotifier",
    "EmailNotifier",
]
