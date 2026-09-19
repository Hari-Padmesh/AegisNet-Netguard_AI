"""
netguard/notifier
-----------------
Notification dispatchers (Webhooks, Email, etc.)
"""

from netguard.notifier.webhook import WebhookNotifier
from netguard.notifier.email_notifier import EmailNotifier

__all__ = ["WebhookNotifier", "EmailNotifier"]
