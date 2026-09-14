"""
netguard/notifier/webhook.py
----------------------------
Real-time webhook notification dispatcher.
Supports Discord, Slack, and generic JSON webhook endpoints with
rate-limiting and background non-blocking execution.
"""

import json
import logging
import threading
import time
from typing import Optional, Dict, Any

import requests

from netguard.alerts import Alert, Severity

logger = logging.getLogger("netguard.notifier.webhook")


class WebhookNotifier:
    """
    Sends real-time attack notifications to Webhook endpoints (Discord, Slack, or generic).

    Parameters
    ----------
    url : str
        The webhook URL.
    service : str, optional
        "auto", "discord", "slack", or "generic". If "auto", infers from URL.
    min_severity : Severity
        Minimum severity to trigger webhook (default: Severity.MEDIUM).
    cooldown_seconds : float
        Minimum time (seconds) between webhook alerts for the same attack type.
    """

    def __init__(
        self,
        url: str,
        service: str = "auto",
        min_severity: Severity = Severity.MEDIUM,
        cooldown_seconds: float = 10.0,
    ):
        self.url = url
        self.service = self._detect_service(url) if service == "auto" else service.lower()
        self.min_severity = min_severity
        self.cooldown_seconds = cooldown_seconds
        self._last_sent: Dict[str, float] = {}
        self._lock = threading.Lock()

        # Severity ranks
        self._severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def _detect_service(self, url: str) -> str:
        if "discord.com" in url or "discordapp.com" in url:
            return "discord"
        if "hooks.slack.com" in url:
            return "slack"
        return "generic"

    def _severity_rank(self, s: Severity) -> int:
        try:
            return self._severity_order.index(s)
        except ValueError:
            return 0

    def should_send(self, alert: Alert) -> bool:
        """Check if alert meets severity threshold and cooldown policy."""
        if self._severity_rank(alert.severity) < self._severity_rank(self.min_severity):
            return False

        now = time.time()
        key = f"{alert.severity.value}:{alert.label}"
        with self._lock:
            last = self._last_sent.get(key, 0.0)
            if now - last < self.cooldown_seconds:
                return False
            self._last_sent[key] = now
        return True

    def send(self, alert: Alert, async_dispatch: bool = True) -> None:
        """
        Send alert to configured webhook. Dispatches in a background thread by default.
        """
        if not self.should_send(alert):
            return

        if async_dispatch:
            thread = threading.Thread(
                target=self._dispatch,
                args=(alert,),
                daemon=True,
                name=f"netguard-webhook-{alert.label}"
            )
            thread.start()
        else:
            self._dispatch(alert)

    def _dispatch(self, alert: Alert) -> None:
        try:
            if self.service == "discord":
                payload = self._build_discord_payload(alert)
            elif self.service == "slack":
                payload = self._build_slack_payload(alert)
            else:
                payload = self._build_generic_payload(alert)

            response = requests.post(
                self.url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if response.status_code >= 400:
                logger.warning(
                    f"Webhook POST failed with status {response.status_code}: {response.text}"
                )
        except Exception as e:
            logger.error(f"Error dispatching webhook alert: {e}")

    def _build_generic_payload(self, alert: Alert) -> Dict[str, Any]:
        return {
            "event": "NETGUARD_ATTACK_ALERT",
            "timestamp": alert.timestamp,
            "severity": alert.severity.value,
            "attack_type": alert.label,
            "confidence": alert.confidence,
            "details": alert.flow_summary,
            "probabilities": alert.probabilities,
        }

    def _build_discord_payload(self, alert: Alert) -> Dict[str, Any]:
        # Discord embed color in integer decimal
        color_map = {
            Severity.CRITICAL: 15158332,  # Red #E74C3C
            Severity.HIGH:     15105570,  # Orange #E67E22
            Severity.MEDIUM:   15844367,  # Gold/Yellow #F1C40F
            Severity.LOW:      9807270,   # Grey
            Severity.INFO:     3066993,   # Green
        }
        color = color_map.get(alert.severity, 15158332)
        return {
            "username": "NetGuard AI Guard",
            "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.png",
            "embeds": [
                {
                    "title": f"🚨 Security Alert: {alert.severity.value} Threat Detected",
                    "description": f"**Attack Pattern:** `{alert.label}`\n**Confidence:** `{alert.confidence:.1%}`",
                    "color": color,
                    "fields": [
                        {
                            "name": "Flow / Request Summary",
                            "value": f"`{alert.flow_summary or 'In-App Web Traffic'}`",
                            "inline": False,
                        },
                        {
                            "name": "Timestamp",
                            "value": alert.timestamp,
                            "inline": True,
                        },
                        {
                            "name": "Severity",
                            "value": alert.severity.value,
                            "inline": True,
                        },
                    ],
                    "footer": {
                        "text": "NetGuard AI In-App Threat Protection"
                    },
                }
            ],
        }

    def _build_slack_payload(self, alert: Alert) -> Dict[str, Any]:
        return {
            "text": f"🚨 *[NetGuard AI]* {alert.severity.value} Alert: `{alert.label}` ({alert.confidence:.1%})",
            "attachments": [
                {
                    "color": "#e01e5a" if alert.severity in (Severity.CRITICAL, Severity.HIGH) else "#ecb22e",
                    "fields": [
                        {"title": "Attack Type", "value": alert.label, "short": True},
                        {"title": "Severity", "value": alert.severity.value, "short": True},
                        {"title": "Confidence", "value": f"{alert.confidence:.1%}", "short": True},
                        {"title": "Time", "value": alert.timestamp, "short": True},
                        {"title": "Summary", "value": alert.flow_summary, "short": False},
                    ],
                }
            ],
        }
