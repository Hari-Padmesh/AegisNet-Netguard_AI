"""
netguard/flow_generator.py
---------------------------
Stateful bidirectional network flow aggregator.

Converts individual packets (from live capture or PCAP files) into
CICIDS2017-style flow-level feature vectors that the ML model expects.

A "flow" is a bidirectional stream of packets sharing the same 5-tuple:
    (ip_src, ip_dst, sport, dport, protocol)

The 20 features used by the trained model are computed incrementally as
packets arrive. When a flow ends (TCP FIN/RST or idle timeout), its feature
vector is extracted and passed to the detection engine.

Flow Lifecycle:
    PacketIn → FlowTracker.add_packet() → flow accumulates stats
    → flow.is_finished() or timeout → flow.to_feature_vector()
    → DetectionEngine.predict()
"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# The 20 features selected by RF importance from CICIDS2017.
# The flow_generator produces exactly this feature set in this order.
FLOW_FEATURES = [
    "Bwd Packet Length Std",
    "Bwd Packet Length Mean",
    "Packet Length Variance",
    "Subflow Fwd Bytes",
    "Total Length of Bwd Packets",
    "Average Packet Size",
    "Avg Bwd Segment Size",
    "Max Packet Length",
    "Total Length of Fwd Packets",
    "Packet Length Mean",
    "Bwd Packet Length Max",
    "Subflow Bwd Bytes",
    "Packet Length Std",
    "Bwd Header Length",
    "Fwd Packet Length Max",
    "Subflow Fwd Packets",
    "Destination Port",
    "Avg Fwd Segment Size",
    "Fwd Packet Length Mean",
    "act_data_pkt_fwd",
]

# Seconds of inactivity before a flow is considered complete
IDLE_TIMEOUT = 30.0


def _std(values: List[float]) -> float:
    """Population standard deviation of a list of values."""
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(variance)


def _variance(values: List[float]) -> float:
    """Population variance of a list of values."""
    n = len(values)
    if n == 0:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / n


@dataclass
class NetworkFlow:
    """
    A single bidirectional network flow.

    Accumulates packet-level statistics incrementally and can compute
    CICIDS2017-style feature vectors on demand.
    """
    # 5-tuple identifiers
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # Timestamps
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Forward direction: src_ip:src_port -> dst_ip:dst_port
    fwd_lengths: List[float] = field(default_factory=list)
    fwd_header_len: float = 0.0
    act_data_pkt_fwd: int = 0   # fwd packets with payload > 0

    # Backward direction: dst_ip:dst_port -> src_ip:src_port
    bwd_lengths: List[float] = field(default_factory=list)
    bwd_header_len: float = 0.0

    # Flow termination flags
    fin_seen: bool = False
    rst_seen: bool = False

    def add_packet(
        self,
        payload_len: float,
        header_len: float,
        direction: str,   # "fwd" or "bwd"
        flags: int = 0,   # TCP flags byte (0 for UDP/other)
        timestamp: Optional[float] = None,
    ) -> None:
        """
        Incorporate one packet into the flow statistics.

        Parameters
        ----------
        payload_len : float
            Payload (data) length in bytes.
        header_len : float
            IP+TCP/UDP header length in bytes.
        direction : str
            "fwd" if source matches flow originator, else "bwd".
        flags : int
            TCP flags byte. Used to detect FIN (0x01) and RST (0x04).
        timestamp : float, optional
            Packet capture timestamp (default: current time).
        """
        now = timestamp or time.time()
        self.last_seen = now

        if direction == "fwd":
            self.fwd_lengths.append(payload_len)
            self.fwd_header_len += header_len
            if payload_len > 0:
                self.act_data_pkt_fwd += 1
        else:
            self.bwd_lengths.append(payload_len)
            self.bwd_header_len += header_len

        # Detect flow termination via TCP flags
        if flags & 0x01:  # FIN
            self.fin_seen = True
        if flags & 0x04:  # RST
            self.rst_seen = True

    def is_finished(self) -> bool:
        """True if TCP FIN or RST seen, signaling flow end."""
        return self.fin_seen or self.rst_seen

    def is_idle(self, timeout: float = IDLE_TIMEOUT) -> bool:
        """True if no packets received for longer than timeout seconds."""
        return (time.time() - self.last_seen) > timeout

    @property
    def all_lengths(self) -> List[float]:
        return self.fwd_lengths + self.bwd_lengths

    def to_feature_vector(self) -> Dict[str, float]:
        """
        Compute the 20 CICIDS2017-style features from accumulated stats.
        Returns a dict matching FLOW_FEATURES keys.
        """
        all_lens = self.all_lengths
        fwd = self.fwd_lengths
        bwd = self.bwd_lengths

        total_fwd_bytes = sum(fwd)
        total_bwd_bytes = sum(bwd)
        n_fwd = len(fwd)
        n_bwd = len(bwd)
        n_all = len(all_lens)

        fwd_len_mean = (total_fwd_bytes / n_fwd) if n_fwd > 0 else 0.0
        bwd_len_mean = (total_bwd_bytes / n_bwd) if n_bwd > 0 else 0.0
        all_len_mean = (sum(all_lens) / n_all) if n_all > 0 else 0.0
        all_len_max = max(all_lens) if all_lens else 0.0
        bwd_len_max = max(bwd) if bwd else 0.0
        fwd_len_max = max(fwd) if fwd else 0.0

        return {
            "Bwd Packet Length Std":    _std(bwd),
            "Bwd Packet Length Mean":   bwd_len_mean,
            "Packet Length Variance":   _variance(all_lens),
            "Subflow Fwd Bytes":        total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,
            "Average Packet Size":      all_len_mean,
            "Avg Bwd Segment Size":     bwd_len_mean,
            "Max Packet Length":        all_len_max,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Packet Length Mean":       all_len_mean,
            "Bwd Packet Length Max":    bwd_len_max,
            "Subflow Bwd Bytes":        total_bwd_bytes,
            "Packet Length Std":        _std(all_lens),
            "Bwd Header Length":        self.bwd_header_len,
            "Fwd Packet Length Max":    fwd_len_max,
            "Subflow Fwd Packets":      float(n_fwd),
            "Destination Port":         float(self.dst_port),
            "Avg Fwd Segment Size":     fwd_len_mean,
            "Fwd Packet Length Mean":   fwd_len_mean,
            "act_data_pkt_fwd":         float(self.act_data_pkt_fwd),
        }

    def summary(self) -> str:
        """Human-readable one-line summary of this flow."""
        return (
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"proto={self.protocol} "
            f"fwd_pkts={len(self.fwd_lengths)} bwd_pkts={len(self.bwd_lengths)} "
            f"fwd_bytes={sum(self.fwd_lengths):.0f} bwd_bytes={sum(self.bwd_lengths):.0f}"
        )


FlowKey = Tuple[str, str, int, int, int]


class FlowTracker:
    """
    Maintains an in-memory dictionary of active flows indexed by 5-tuple.

    Handles bidirectional packet assignment: packets going in either direction
    of a connection are assigned to the same flow.

    Usage:
        tracker = FlowTracker()
        for pkt in packets:
            finished = tracker.add_packet(pkt_meta)
            for flow in finished:
                # flow.to_feature_vector() -> send to detection engine
    """

    def __init__(self, idle_timeout: float = IDLE_TIMEOUT):
        self._flows: Dict[FlowKey, NetworkFlow] = {}
        self.idle_timeout = idle_timeout

    def _make_key(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: int) -> Tuple[FlowKey, str]:
        """
        Canonical bidirectional flow key and direction.
        Key always uses (lower_ip, higher_ip, lower_port, higher_port, proto)
        to ensure both directions map to the same flow entry.
        """
        if (src_ip, sport) <= (dst_ip, dport):
            key: FlowKey = (src_ip, dst_ip, sport, dport, proto)
            direction = "fwd"
        else:
            key = (dst_ip, src_ip, dport, sport, proto)
            direction = "bwd"
        return key, direction

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: int,
        payload_len: float,
        header_len: float,
        flags: int = 0,
        timestamp: Optional[float] = None,
    ) -> List[NetworkFlow]:
        """
        Add a packet to the appropriate flow.

        Returns a list of flows that finished as a result of this packet
        (e.g., TCP FIN/RST triggered). These should be passed to the
        detection engine immediately.
        """
        key, direction = self._make_key(src_ip, dst_ip, sport, dport, proto)
        now = timestamp or time.time()

        if key not in self._flows:
            # First packet in this flow — determine canonical src/dst from key
            k_src_ip, k_dst_ip, k_sport, k_dport, k_proto = key
            self._flows[key] = NetworkFlow(
                src_ip=k_src_ip,
                dst_ip=k_dst_ip,
                src_port=k_sport,
                dst_port=k_dport,
                protocol=k_proto,
                start_time=now,
                last_seen=now,
            )

        flow = self._flows[key]
        flow.add_packet(payload_len, header_len, direction, flags, timestamp=now)

        finished: List[NetworkFlow] = []
        if flow.is_finished():
            finished.append(self._flows.pop(key))

        return finished

    def collect_idle_flows(self) -> List[NetworkFlow]:
        """
        Scan active flows for those that have exceeded the idle timeout.
        Removes and returns them so they can be scored.
        """
        idle: List[NetworkFlow] = []
        idle_keys = [k for k, f in self._flows.items() if f.is_idle(self.idle_timeout)]
        for k in idle_keys:
            idle.append(self._flows.pop(k))
        return idle

    def flush_all(self) -> List[NetworkFlow]:
        """
        Force-expire all active flows. Used at end of PCAP processing
        to score any remaining incomplete flows.
        """
        flows = list(self._flows.values())
        self._flows.clear()
        return flows

    @property
    def active_count(self) -> int:
        """Number of currently tracked flows."""
        return len(self._flows)
