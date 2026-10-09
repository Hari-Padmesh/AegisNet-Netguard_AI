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


class ApplicationRuleEngine:
    """Track short-lived per-client HTTP signals and return rule matches."""

    def __init__(self, window_seconds: float = 60.0, burst_threshold: int = 25):
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self._request_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._failed_auth_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._sensitive_paths: Dict[str, Deque[tuple[str, float]]] = defaultdict(deque)

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
        self._trim(request_times, timestamp)

        if _SQLI_PATTERN.search(target):
            return RuleMatch("Web Attack - Sql Injection", 0.99, "http.sqli")
        if _XSS_PATTERN.search(target):
            return RuleMatch("Web Attack - XSS", 0.99, "http.xss")
        if _PATH_TRAVERSAL_PATTERN.search(target):
            return RuleMatch("Web Attack - Path Traversal", 0.99, "http.path_traversal")

        if status_code in (401, 403):
            failed_auth = self._failed_auth_times[client_ip]
            failed_auth.append(timestamp)
            self._trim(failed_auth, timestamp)
            if len(failed_auth) >= 5:
                return RuleMatch("BruteForce", 0.95, "http.failed_auth_burst")

        normalized_path = path.rstrip("/") or "/"
        if normalized_path in _SENSITIVE_PATHS:
            paths = self._sensitive_paths[client_ip]
            paths.append((normalized_path, timestamp))
            while paths and timestamp - paths[0][1] > self.window_seconds:
                paths.popleft()
            unique_paths: Set[str] = {item[0] for item in paths}
            if len(unique_paths) >= 3:
                return RuleMatch("PortScan", 0.95, "http.sensitive_path_scan")

        if len(request_times) >= self.burst_threshold:
            return RuleMatch("DoS", 0.95, "http.request_burst")

        return None

    def _trim(self, timestamps: Deque[float], now: float) -> None:
        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()