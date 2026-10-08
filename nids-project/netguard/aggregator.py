"""
netguard/aggregator.py
----------------------
HTTP request aggregator that builds CICIDS-style flow feature vectors
from FastAPI/web application traffic (no raw packet capture required).

Each client IP is tracked over a sliding time window. Request/response byte
sizes are treated as forward/backward packet lengths for ML classification.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from netguard.flow_generator import FLOW_FEATURES


def _std(values: List[float]) -> float:
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)


def _variance(values: List[float]) -> float:
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / n


def _parse_port(host: Optional[str], default: int = 80) -> int:
    if not host:
        return default
    parsed = urlparse(f"//{host}" if "://" not in host else host)
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    return default


@dataclass
class HttpFlow:
    """Aggregated HTTP traffic for one client within a time window."""

    client_ip: str
    destination_port: int
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    fwd_lengths: List[float] = field(default_factory=list)
    bwd_lengths: List[float] = field(default_factory=list)
    act_data_pkt_fwd: int = 0

    request_count: int = 0
    paths: List[str] = field(default_factory=list)

    def add_exchange(
        self,
        req_bytes: float,
        resp_bytes: float,
        path: str = "",
        timestamp: Optional[float] = None,
    ) -> None:
        now = timestamp or time.time()
        self.last_seen = now
        self.request_count += 1
        if path:
            self.paths.append(path)

        req_bytes = max(float(req_bytes), 0.0)
        resp_bytes = max(float(resp_bytes), 0.0)

        self.fwd_lengths.append(req_bytes)
        self.bwd_lengths.append(resp_bytes)
        if req_bytes > 0:
            self.act_data_pkt_fwd += 1

    def is_idle(self, timeout: float) -> bool:
        return (time.time() - self.last_seen) > timeout

    @property
    def all_lengths(self) -> List[float]:
        return self.fwd_lengths + self.bwd_lengths

    def to_feature_vector(self) -> Dict[str, float]:
        """Map HTTP aggregates to the 20 ML model features."""
        all_lens = self.all_lengths
        fwd = self.fwd_lengths
        bwd = self.bwd_lengths

        total_fwd = sum(fwd)
        total_bwd = sum(bwd)
        n_fwd = len(fwd)
        n_bwd = len(bwd)
        n_all = len(all_lens)

        fwd_mean = (total_fwd / n_fwd) if n_fwd else 0.0
        bwd_mean = (total_bwd / n_bwd) if n_bwd else 0.0
        all_mean = (sum(all_lens) / n_all) if n_all else 0.0

        return {
            "Bwd Packet Length Std": _std(bwd),
            "Bwd Packet Length Mean": bwd_mean,
            "Packet Length Variance": _variance(all_lens),
            "Subflow Fwd Bytes": total_fwd,
            "Total Length of Bwd Packets": total_bwd,
            "Average Packet Size": all_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Max Packet Length": max(all_lens) if all_lens else 0.0,
            "Total Length of Fwd Packets": total_fwd,
            "Packet Length Mean": all_mean,
            "Bwd Packet Length Max": max(bwd) if bwd else 0.0,
            "Subflow Bwd Bytes": total_bwd,
            "Packet Length Std": _std(all_lens),
            "Bwd Header Length": float(n_bwd * 20),
            "Fwd Packet Length Max": max(fwd) if fwd else 0.0,
            "Subflow Fwd Packets": float(n_fwd),
            "Destination Port": float(self.destination_port),
            "Avg Fwd Segment Size": fwd_mean,
            "Fwd Packet Length Mean": fwd_mean,
            "act_data_pkt_fwd": float(self.act_data_pkt_fwd),
        }

    def summary(self) -> str:
        path_hint = self.paths[-1] if self.paths else "/"
        return (
            f"HTTP {self.client_ip} -> :{int(self.destination_port)} "
            f"requests={self.request_count} path={path_hint} "
            f"fwd_bytes={sum(self.fwd_lengths):.0f} bwd_bytes={sum(self.bwd_lengths):.0f}"
        )


FlowKey = Tuple[str, int]


class HttpFlowAggregator:
    """
    Tracks per-client HTTP traffic and emits completed flows for ML scoring.

    Parameters
    ----------
    window_seconds : float
        Idle time before a client flow is closed and returned for classification.
    """

    def __init__(self, window_seconds: float = 30.0):
        self.window_seconds = window_seconds
        self._flows: Dict[FlowKey, HttpFlow] = {}

    def add_request(
        self,
        client_ip: str,
        req_bytes: float,
        resp_bytes: float,
        dest_port: int = 80,
        path: str = "",
        timestamp: Optional[float] = None,
    ) -> List[HttpFlow]:
        """
        Record one HTTP exchange. Returns flows that exceeded the idle window.
        """
        key: FlowKey = (client_ip, dest_port)
        now = timestamp or time.time()

        if key not in self._flows:
            self._flows[key] = HttpFlow(
                client_ip=client_ip,
                destination_port=dest_port,
                start_time=now,
                last_seen=now,
            )

        flow = self._flows[key]
        flow.add_exchange(req_bytes, resp_bytes, path=path, timestamp=now)

        completed: List[HttpFlow] = []
        idle_keys = [k for k, f in self._flows.items() if f.is_idle(self.window_seconds)]
        for k in idle_keys:
            completed.append(self._flows.pop(k))
        return completed

    def collect_idle_flows(self) -> List[HttpFlow]:
        """Force-close all flows that exceeded the idle timeout."""
        idle: List[HttpFlow] = []
        idle_keys = [k for k, f in self._flows.items() if f.is_idle(self.window_seconds)]
        for k in idle_keys:
            idle.append(self._flows.pop(k))
        return idle

    def flush_all(self) -> List[HttpFlow]:
        """Return and clear all active flows (e.g. on shutdown)."""
        flows = list(self._flows.values())
        self._flows.clear()
        return flows

    @property
    def active_count(self) -> int:
        return len(self._flows)

    @staticmethod
    def dest_port_from_request(host: Optional[str], scheme: str = "http") -> int:
        port = _parse_port(host)
        if port:
            return port
        return 443 if scheme == "https" else 80
