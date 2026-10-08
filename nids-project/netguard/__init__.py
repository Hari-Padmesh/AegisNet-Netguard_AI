"""
NetGuard AI — Embeddable Network Intrusion Detection System
============================================================
Import NetGuard in any FastAPI project to monitor HTTP traffic and
alert on ML-detected threats without admin privileges.
"""

from netguard.alerts import Alert, Severity
from netguard.config import DashboardMode, NetGuardConfig
from netguard.core import NetGuard
from netguard.detection import DetectionEngine, PredictionResult

__version__ = "0.2.0"
__author__ = "NetGuard AI"

__all__ = [
    "Alert",
    "DashboardMode",
    "DetectionEngine",
    "NetGuard",
    "NetGuardConfig",
    "PredictionResult",
    "Severity",
    "__version__",
]
