"""
Application-layer rules for HTTP traffic.

These rules complement the CICIDS-trained flow model. They are intentionally
deterministic and operate on request data that middleware can actually see.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Set

from netguard.config import DEFAULT_RULE_COOLDOWNS


_SQLI_PATTERN = re.compile(
    r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|TABLE|FROM|WHERE|BENCHMARK|SLEEP)\b|--|' OR 1=1|\bOR '1'='1)",
    re.IGNORECASE,
)
_XSS_PATTERN = re.compile(
    r"(<script|javascript:|onload=|onerror=|onclick=|<iframe|<img\s+src=)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini)",
    re.IGNORECASE,
)
_AUTH_PATH_PATTERN = re.compile(
    r"/(login|signin|sign-in|auth|oauth|token|session|password|authenticate)(?:/|$)",
    re.IGNORECASE,
)

_SENSITIVE_PATHS = {
    "/.env",
    "/.git/config",
    "/admin",
    "/actuator",
    "/actuator/health",
    "/config.json",
    "/console",
    "/phpmyadmin",
    "/server-status",
    "/wp-login.php",
}


@dataclass(frozen=True)
class RuleMatch:
    """A deterministic application-layer detection result."""

    label: str
    confidence: float
    rule_id: str
    alert_suppressed: bool = False


class ApplicationRuleEngine:
    """Track short-lived per-client HTTP signals and return rule matches."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        burst_window_seconds: float = 2.0,
        burst_threshold: int = 25,
        cooldowns: Optional[Dict[str, float]] = None,
    ):
        self.window_seconds = window_seconds
        self.burst_window_seconds = burst_window_seconds
        self.burst_threshold = burst_threshold
        self.cooldowns = dict(DEFAULT_RULE_COOLDOWNS)
        if cooldowns is not None:
            self.cooldowns.update({key: max(0.0, float(value)) for key, value in cooldowns.items()})
        self._request_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._failed_auth_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._sensitive_paths: Dict[str, Deque[tuple[str, float]]] = defaultdict(deque)
        self._last_alerted: Dict[tuple[str, str], float] = {}

    def evaluate(
        self,
        client_ip: str,
        path: str,
        query_string: str = "",
        status_code: int = 200,
        now: Optional[float] = None,
    ) -> Optional[RuleMatch]:
        timestamp = time.monotonic() if now is None else now
        target = f"{path}?{query_string}" if query_string else path

        request_times = self._request_times[client_ip]
        request_times.append(timestamp)
        self._trim(request_times, timestamp, self.burst_window_seconds)

        if _SQLI_PATTERN.search(target):
            return self._match(client_ip, timestamp, "Web Attack - Sql Injection", 0.99, "http.sqli")
        if _XSS_PATTERN.search(target):
            return self._match(client_ip, timestamp, "Web Attack - XSS", 0.99, "http.xss")
        if _PATH_TRAVERSAL_PATTERN.search(target):
            return self._match(client_ip, timestamp, "Web Attack - Path Traversal", 0.99, "http.path_traversal")

        normalized_path = path.rstrip("/") or "/"
        if status_code in (401, 403) and _AUTH_PATH_PATTERN.search(normalized_path):
            failed_auth = self._failed_auth_times[client_ip]
            failed_auth.append(timestamp)
            self._trim(failed_auth, timestamp, self.window_seconds)
            if len(failed_auth) >= 5:
                return self._match(client_ip, timestamp, "BruteForce", 0.95, "http.failed_auth_burst")

        if normalized_path in _SENSITIVE_PATHS:
            paths = self._sensitive_paths[client_ip]
            paths.append((normalized_path, timestamp))
            while paths and timestamp - paths[0][1] > self.window_seconds:
                paths.popleft()
            unique_paths: Set[str] = {item[0] for item in paths}
            if len(unique_paths) >= 3:
                return self._match(client_ip, timestamp, "PortScan", 0.95, "http.sensitive_path_scan")

        if len(request_times) >= self.burst_threshold:
            return self._match(client_ip, timestamp, "DoS", 0.95, "http.request_burst")

        return None

    def _match(
        self,
        client_ip: str,
        timestamp: float,
        label: str,
        confidence: float,
        rule_id: str,
    ) -> RuleMatch:
        cooldown = self.cooldowns.get(rule_id, 0.0)
        key = (client_ip, rule_id)
        previous = self._last_alerted.get(key)
        suppressed = previous is not None and timestamp - previous < cooldown
        if not suppressed:
            self._last_alerted[key] = timestamp
        return RuleMatch(label, confidence, rule_id, alert_suppressed=suppressed)

    def _trim(self, timestamps: Deque[float], now: float, window_seconds: float) -> None:
        while timestamps and now - timestamps[0] > window_seconds:
            timestamps.popleft()
