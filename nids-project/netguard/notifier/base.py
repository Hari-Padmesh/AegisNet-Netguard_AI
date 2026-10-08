"""
netguard/notifier/base.py
-------------------------
Base protocol for alert notification channels.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netguard.alerts import Alert


class AlertNotifier(ABC):
    """Deliver a NetGuard alert to an external channel."""

    @abstractmethod
    def notify(self, alert: "Alert") -> None:
        """Send the alert. Implementations should not raise on transient failures."""

    @property
    def name(self) -> str:
        return self.__class__.__name__
