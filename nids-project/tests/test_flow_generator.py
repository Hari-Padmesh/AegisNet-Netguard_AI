"""
tests/test_flow_generator.py
-----------------------------
Unit tests for the stateful network flow aggregator.

Tests cover:
  - Bidirectional 5-tuple key canonicalization
  - Feature vector computation (correct fields and types)
  - Flow lifecycle: FIN flag triggers flow completion
  - Idle timeout detection
  - FlushAll drains all active flows
"""

import math
import time
import pytest

from netguard.flow_generator import NetworkFlow, FlowTracker, FLOW_FEATURES


# ──────────────────────────────────────────────────────────────────────────────
#  NetworkFlow unit tests
# ──────────────────────────────────────────────────────────────────────────────

class TestNetworkFlow:

    def _make_flow(self):
        return NetworkFlow(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=54321, dst_port=80, protocol=6,
        )

    def test_feature_vector_keys(self):
        """Feature vector must contain exactly the 20 expected feature names."""
        flow = self._make_flow()
        flow.add_packet(100.0, 40.0, "fwd")
        fv = flow.to_feature_vector()
        assert set(fv.keys()) == set(FLOW_FEATURES), \
            f"Missing/extra keys: {set(fv.keys()) ^ set(FLOW_FEATURES)}"

    def test_feature_vector_types(self):
        """All feature values must be floats."""
        flow = self._make_flow()
        flow.add_packet(200.0, 40.0, "fwd")
        flow.add_packet(150.0, 40.0, "bwd")
        fv = flow.to_feature_vector()
        for k, v in fv.items():
            assert isinstance(v, float), f"Feature {k} has type {type(v)}, expected float"

    def test_fwd_bwd_accounting(self):
        """Fwd and bwd packet stats are tracked separately and correctly."""
        flow = self._make_flow()
        flow.add_packet(100.0, 40.0, "fwd")
        flow.add_packet(200.0, 40.0, "fwd")
        flow.add_packet(50.0,  40.0, "bwd")

        fv = flow.to_feature_vector()
        assert fv["Total Length of Fwd Packets"] == 300.0
        assert fv["Total Length of Bwd Packets"] == 50.0
        assert fv["Subflow Fwd Packets"] == 2.0
        assert fv["Fwd Packet Length Mean"] == pytest.approx(150.0)
        assert fv["Bwd Packet Length Mean"] == pytest.approx(50.0)

    def test_max_packet_length(self):
        """Max packet length should be the global maximum across fwd + bwd."""
        flow = self._make_flow()
        flow.add_packet(100.0, 20.0, "fwd")
        flow.add_packet(500.0, 20.0, "bwd")
        flow.add_packet(200.0, 20.0, "fwd")
        fv = flow.to_feature_vector()
        assert fv["Max Packet Length"] == 500.0

    def test_act_data_pkt_fwd(self):
        """act_data_pkt_fwd counts only forward packets with payload > 0."""
        flow = self._make_flow()
        flow.add_packet(0.0,   20.0, "fwd")   # no payload — not counted
        flow.add_packet(100.0, 20.0, "fwd")   # counted
        flow.add_packet(200.0, 20.0, "fwd")   # counted
        flow.add_packet(50.0,  20.0, "bwd")   # bwd — not counted
        fv = flow.to_feature_vector()
        assert fv["act_data_pkt_fwd"] == 2.0

    def test_empty_flow_no_crash(self):
        """A flow with no packets should return zero for all features."""
        flow = self._make_flow()
        fv = flow.to_feature_vector()
        for k, v in fv.items():
            # Destination Port is set at construction time; others should be 0
            if k != "Destination Port":
                assert v == 0.0, f"Expected 0.0 for {k}, got {v}"

    def test_destination_port(self):
        """Destination Port must equal the dst_port used in construction."""
        flow = NetworkFlow("1.2.3.4", "5.6.7.8", 9999, 443, 6)
        fv = flow.to_feature_vector()
        assert fv["Destination Port"] == 443.0

    def test_fin_flag_marks_finished(self):
        """FIN TCP flag (0x01) should mark flow as finished."""
        flow = self._make_flow()
        flow.add_packet(100.0, 20.0, "fwd", flags=0x00)
        assert not flow.is_finished()
        flow.add_packet(100.0, 20.0, "fwd", flags=0x01)   # FIN
        assert flow.is_finished()

    def test_rst_flag_marks_finished(self):
        """RST TCP flag (0x04) should mark flow as finished."""
        flow = self._make_flow()
        flow.add_packet(100.0, 20.0, "fwd", flags=0x04)   # RST
        assert flow.is_finished()

    def test_bwd_header_length(self):
        """Backward header length accumulates across bwd packets."""
        flow = self._make_flow()
        flow.add_packet(0.0, 30.0, "bwd")
        flow.add_packet(0.0, 40.0, "bwd")
        fv = flow.to_feature_vector()
        assert fv["Bwd Header Length"] == pytest.approx(70.0)

    def test_std_and_variance_correctness(self):
        """Verify packet length std and variance against manual computation."""
        flow = self._make_flow()
        lengths = [100.0, 200.0, 300.0]
        for l in lengths:
            flow.add_packet(l, 20.0, "fwd")
        fv = flow.to_feature_vector()
        mean = sum(lengths) / len(lengths)
        expected_variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        expected_std = math.sqrt(expected_variance)
        assert fv["Packet Length Variance"] == pytest.approx(expected_variance, rel=1e-5)
        assert fv["Packet Length Std"] == pytest.approx(expected_std, rel=1e-5)


# ──────────────────────────────────────────────────────────────────────────────
#  FlowTracker unit tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFlowTracker:

    def _pkt(self, src, dst, sp, dp, proto=6, payload=100.0, header=40.0, flags=0, ts=None):
        """Helper to call tracker.add_packet with sane defaults."""
        return self.tracker.add_packet(src, dst, sp, dp, proto, payload, header, flags, ts)

    def setup_method(self):
        self.tracker = FlowTracker(idle_timeout=1.0)

    def test_bidirectional_same_flow(self):
        """Packets in both directions of a connection map to one flow."""
        self._pkt("10.0.0.1", "10.0.0.2", 12345, 80)
        self._pkt("10.0.0.2", "10.0.0.1", 80, 12345)   # reverse direction
        assert self.tracker.active_count == 1

    def test_different_5tuples_different_flows(self):
        """Different port pairs should produce distinct flows."""
        self._pkt("10.0.0.1", "10.0.0.2", 11111, 80)
        self._pkt("10.0.0.1", "10.0.0.2", 22222, 80)
        assert self.tracker.active_count == 2

    def test_fin_completes_flow(self):
        """A FIN packet should pop the flow from active and return it."""
        self._pkt("10.0.0.1", "10.0.0.2", 5001, 80, flags=0x00)
        finished = self._pkt("10.0.0.1", "10.0.0.2", 5001, 80, flags=0x01)
        assert len(finished) == 1
        assert self.tracker.active_count == 0

    def test_collect_idle_flows(self):
        """Idle flows (beyond timeout) should be collected and removed."""
        past_ts = time.time() - 60.0   # 60 seconds ago
        self._pkt("10.0.0.1", "10.0.0.2", 9001, 80, ts=past_ts)
        assert self.tracker.active_count == 1
        idle = self.tracker.collect_idle_flows()
        assert len(idle) == 1
        assert self.tracker.active_count == 0

    def test_flush_all(self):
        """flush_all should drain every active flow."""
        for port in range(10):
            self._pkt("10.0.0.1", "10.0.0.2", 5000 + port, 80)
        assert self.tracker.active_count == 10
        all_flows = self.tracker.flush_all()
        assert len(all_flows) == 10
        assert self.tracker.active_count == 0

    def test_flushed_flows_have_feature_vectors(self):
        """Flushed flows must produce valid feature vectors."""
        self._pkt("192.168.1.1", "8.8.8.8", 53211, 53, proto=17, payload=60.0, header=28.0)
        flows = self.tracker.flush_all()
        assert len(flows) == 1
        fv = flows[0].to_feature_vector()
        assert set(fv.keys()) == set(FLOW_FEATURES)
        assert fv["Destination Port"] == 53.0
