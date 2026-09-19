"""
netguard/integrations/base.py
-----------------------------
Core application traffic monitor and flow aggregator for web applications.
Captures request/response streams in unprivileged user space (zero admin required),
computes flow statistics, scores threats via DetectionEngine, and handles auto-blocking.
"""

import math
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any

from netguard.detection import DetectionEngine, PredictionResult
from netguard.alerts import AlertManager, Alert, Severity


# Web attack signatures for application layer inspection
_SQLI_PATTERN = re.compile(
    r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|TABLE|FROM|WHERE|BENCHMARK|SLEEP)\b|--|' OR 1=1|\bOR '1'='1)",
    re.IGNORECASE,
)
_XSS_PATTERN = re.compile(
    r"(<script|javascript:|onload=|onerror=|onclick=|<iframe|<img\s+src=)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini)",
    re.IGNORECASE,
)
_COMMON_SCAN_PATHS = {
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/actuator",
    "/config.json", "/api/v1/debug", "/server-status", "/console",
    "/xmlrpc.php", "/vendor/.env", "/.git/config"
}


@dataclass
class ClientSessionStats:
    """Tracks state and rolling metrics for a single client IP."""
    client_ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0
    attack_count: int = 0
    fwd_lengths: List[float] = field(default_factory=list)
    bwd_lengths: List[float] = field(default_factory=list)
    recent_timestamps: List[float] = field(default_factory=list)
    error_count: int = 0
    scanned_paths_log: List[Tuple[str, float]] = field(default_factory=list)
    last_attack_type: Optional[str] = None

    def record_request(
        self,
        fwd_bytes: float,
        bwd_bytes: float,
        path: str,
        status_code: int,
        timestamp: float,
    ) -> None:
        self.last_seen = timestamp
        self.request_count += 1
        self.fwd_lengths.append(fwd_bytes)
        self.bwd_lengths.append(bwd_bytes)
        self.recent_timestamps.append(timestamp)

        # Keep rolling window of last 50 requests
        if len(self.fwd_lengths) > 50:
            self.fwd_lengths.pop(0)
        if len(self.bwd_lengths) > 50:
            self.bwd_lengths.pop(0)

        # Clean timestamps older than 10 seconds
        cutoff = timestamp - 10.0
        self.recent_timestamps = [t for t in self.recent_timestamps if t >= cutoff]

        if status_code >= 400:
            self.error_count += 1
        if status_code == 404 and path in _COMMON_SCAN_PATHS:
            self.scanned_paths_log.append((path, timestamp))

    @property
    def recent_scanned_paths(self) -> Set[str]:
        """Unique scan paths hit within the last 60 seconds."""
        cutoff = time.time() - 60.0
        self.scanned_paths_log = [(p, t) for p, t in self.scanned_paths_log if t >= cutoff]
        return {p for p, _ in self.scanned_paths_log}

    @property
    def request_rate(self) -> float:
        """Requests per second in the last 10 seconds."""
        if not self.recent_timestamps:
            return 0.0
        window = max(1.0, time.time() - self.recent_timestamps[0])
        return len(self.recent_timestamps) / window


class AppTrafficMonitor:
    """
    In-App traffic analyzer and threat classifier.
    Works inside web framework middleware without administrative privileges.

    Parameters
    ----------
    engine : DetectionEngine, optional
        Trained detection engine. If None, auto-loads bundled model.
    alert_manager : AlertManager, optional
        Alert manager instance. If None, creates a default one.
    block_attacks : bool
        Whether to automatically block IPs identified in high-severity attacks.
    block_duration_seconds : float
        How long an IP remains blocked (default 300 seconds / 5 mins).
    """

    def __init__(
        self,
        engine: Optional[DetectionEngine] = None,
        alert_manager: Optional[AlertManager] = None,
        block_attacks: bool = False,
        block_duration_seconds: float = 300.0,
    ):
        if engine is not None:
            self.engine = engine
        else:
            self.engine = DetectionEngine().load()

        self.alert_manager = alert_manager or AlertManager(console_output=False)
        self.block_attacks = block_attacks
        self.block_duration_seconds = block_duration_seconds

        self._lock = threading.Lock()
        self._clients: Dict[str, ClientSessionStats] = {}
        self._blocked_ips: Dict[str, float] = {}  # ip -> unblock_timestamp
        self._total_requests = 0
        self._total_attacks = 0
        self._recent_events: List[Dict[str, Any]] = []

    def is_ip_blocked(self, client_ip: str) -> bool:
        """Check if an IP is actively blocked."""
        now = time.time()
        with self._lock:
            if client_ip in self._blocked_ips:
                if now < self._blocked_ips[client_ip]:
                    return True
                else:
                    del self._blocked_ips[client_ip]
        return False

    def block_ip(self, client_ip: str, duration: Optional[float] = None) -> None:
        """Manually block an IP."""
        dur = duration if duration is not None else self.block_duration_seconds
        with self._lock:
            self._blocked_ips[client_ip] = time.time() + dur

    def unblock_ip(self, client_ip: str) -> None:
        """Manually unblock an IP."""
        with self._lock:
            self._blocked_ips.pop(client_ip, None)

    def get_blocked_ips(self) -> Dict[str, float]:
        """Return dict of currently blocked IPs and remaining seconds."""
        now = time.time()
        with self._lock:
            active = {}
            for ip, exp in list(self._blocked_ips.items()):
                remaining = exp - now
                if remaining > 0:
                    active[ip] = round(remaining, 1)
                else:
                    del self._blocked_ips[ip]
            return active

    def analyze_request(
        self,
        client_ip: str,
        client_port: int,
        server_port: int,
        method: str,
        path: str,
        query_string: str,
        headers: Dict[str, str],
        request_bytes: int,
        response_bytes: int,
        status_code: int,
        duration: float,
    ) -> PredictionResult:
        """
        Process an incoming HTTP request/response cycle, update statistics,
        score threat likelihood, and trigger alerts if an attack is detected.
        """
        now = time.time()

        with self._lock:
            self._total_requests += 1
            if client_ip not in self._clients:
                self._clients[client_ip] = ClientSessionStats(client_ip=client_ip)
            stats = self._clients[client_ip]
            stats.record_request(request_bytes, response_bytes, path, status_code, now)

        # 1. Check for explicit Web Application Attack patterns in URI, query, headers
        url_target = f"{path}?{query_string}" if query_string else path
        web_attack_detected = None

        if _SQLI_PATTERN.search(url_target):
            web_attack_detected = "Web Attack - Sql Injection"
        elif _XSS_PATTERN.search(url_target):
            web_attack_detected = "Web Attack - XSS"
        elif _PATH_TRAVERSAL.search(url_target):
            web_attack_detected = "Web Attack - Brute Force"
        elif stats.request_rate > 35.0:
            web_attack_detected = "DoS"
        elif path in _COMMON_SCAN_PATHS and len(stats.recent_scanned_paths) >= 3:
            web_attack_detected = "PortScan"

        # 2. Build flow feature vector compatible with DetectionEngine
        fwd = stats.fwd_lengths or [float(request_bytes)]
        bwd = stats.bwd_lengths or [float(response_bytes)]
        all_lengths = fwd + bwd

        fwd_mean = sum(fwd) / len(fwd)
        bwd_mean = sum(bwd) / len(bwd)
        all_mean = sum(all_lengths) / len(all_lengths)

        fwd_max = max(fwd)
        bwd_max = max(bwd)
        all_max = max(all_lengths)

        bwd_var = sum((x - bwd_mean) ** 2 for x in bwd) / len(bwd)
        bwd_std = math.sqrt(bwd_var)
        all_var = sum((x - all_mean) ** 2 for x in all_lengths) / len(all_lengths)
        all_std = math.sqrt(all_var)

        total_fwd_bytes = sum(fwd)
        total_bwd_bytes = sum(bwd)

        feature_dict = {
            "Bwd Packet Length Std": bwd_std,
            "Bwd Packet Length Mean": bwd_mean,
            "Packet Length Variance": all_var,
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,
            "Average Packet Size": all_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Max Packet Length": all_max,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Packet Length Mean": all_mean,
            "Bwd Packet Length Max": bwd_max,
            "Subflow Bwd Bytes": total_bwd_bytes,
            "Packet Length Std": all_std,
            "Bwd Header Length": float(len(headers) * 32),
            "Fwd Packet Length Max": fwd_max,
            "Subflow Fwd Packets": float(len(fwd)),
            "Destination Port": float(server_port),
            "Avg Fwd Segment Size": fwd_mean,
            "Fwd Packet Length Mean": fwd_mean,
            "act_data_pkt_fwd": float(sum(1 for x in fwd if x > 0)),
        }

        flow_summary = f"{client_ip}:{client_port} -> :{server_port} | {method} {path} [{status_code}]"

        # 3. Predict using the ML engine
        pred_result = self.engine.predict(feature_dict, flow_summary=flow_summary)

        # 4. If an explicit web signature matched and confidence is high, override or escalate
        if web_attack_detected:
            pred_result.label = web_attack_detected
            pred_result.is_attack = True
            pred_result.confidence = max(pred_result.confidence, 0.92)

        # 5. Handle attack events
        if pred_result.is_attack:
            with self._lock:
                self._total_attacks += 1
                stats.attack_count += 1
                stats.last_attack_type = pred_result.label

            # Trigger alert
            alert = self.alert_manager.trigger(pred_result)

            # Auto-block IP if enabled and high severity
            if self.block_attacks and pred_result.confidence >= 0.70:
                self.block_ip(client_ip)

            # Record event for dashboard stream
            with self._lock:
                event_entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "client_ip": client_ip,
                    "method": method,
                    "path": path,
                    "label": pred_result.label,
                    "confidence": round(pred_result.confidence, 3),
                    "is_attack": True,
                }
                self._recent_events.append(event_entry)
                if len(self._recent_events) > 100:
                    self._recent_events.pop(0)
        else:
            with self._lock:
                if len(self._recent_events) < 50 or self._total_requests % 5 == 0:
                    self._recent_events.append({
                        "timestamp": time.strftime("%H:%M:%S"),
                        "client_ip": client_ip,
                        "method": method,
                        "path": path,
                        "label": "BENIGN",
                        "confidence": round(pred_result.confidence, 3),
                        "is_attack": False,
                    })
                    if len(self._recent_events) > 100:
                        self._recent_events.pop(0)

        return pred_result

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics for telemetry and dashboard."""
        with self._lock:
            total_req = self._total_requests
            total_att = self._total_attacks
            alert_stats = self.alert_manager.stats()

            # Top client IPs by request count
            sorted_clients = sorted(
                self._clients.values(),
                key=lambda c: (c.attack_count > 0, c.request_count),
                reverse=True,
            )[:15]

            clients_summary = [
                {
                    "ip": c.client_ip,
                    "requests": c.request_count,
                    "attacks": c.attack_count,
                    "rate": round(c.request_rate, 1),
                    "last_attack": c.last_attack_type,
                    "is_blocked": c.client_ip in self._blocked_ips,
                }
                for c in sorted_clients
            ]

            recent_events = list(self._recent_events[-30:])

        # Calculate threat level (DEFCON / Matrix style)
        if total_att == 0:
            threat_level = "NOMINAL"
            threat_color = "emerald"
        elif total_att < 5:
            threat_level = "ELEVATED"
            threat_color = "amber"
        else:
            threat_level = "CRITICAL"
            threat_color = "crimson"

        return {
            "total_requests": total_req,
            "total_attacks": total_att,
            "benign_requests": max(0, total_req - total_att),
            "threat_level": threat_level,
            "threat_color": threat_color,
            "blocked_ips_count": len(self.get_blocked_ips()),
            "attacks_by_label": alert_stats["by_label"],
            "attacks_by_severity": alert_stats["by_severity"],
            "top_clients": clients_summary,
            "recent_events": recent_events,
        }
