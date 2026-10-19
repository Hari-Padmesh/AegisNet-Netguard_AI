"""
netguard/notifier
-----------------
Pluggable alert delivery channels for NetGuard.
"""

from netguard.notifier.base import AlertNotifier
from netguard.notifier.dashboard import DashboardEventNotifier
from netguard.notifier.email import EmailNotifier
from netguard.notifier.webhook import WebhookNotifier

__all__ = [
    "AlertNotifier",
    "DashboardEventNotifier",
    "EmailNotifier",
    "WebhookNotifier",
]

