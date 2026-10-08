"""Tests for HTTP flow aggregation."""

import time

from netguard.aggregator import HttpFlow, HttpFlowAggregator


def test_http_flow_feature_vector_has_all_model_features():
    flow = HttpFlow(client_ip="10.0.0.1", destination_port=443)
    flow.add_exchange(req_bytes=512, resp_bytes=1024, path="/api")
    flow.add_exchange(req_bytes=256, resp_bytes=2048, path="/api/data")

    features = flow.to_feature_vector()
    assert "Destination Port" in features
    assert features["Destination Port"] == 443.0
    assert features["Subflow Fwd Packets"] == 2.0
    assert features["act_data_pkt_fwd"] == 2.0


def test_aggregator_emits_flow_after_idle_window():
    agg = HttpFlowAggregator(window_seconds=0.05)
    agg.add_request("192.168.1.5", req_bytes=100, resp_bytes=200, dest_port=80, path="/")
    time.sleep(0.06)
    completed = agg.collect_idle_flows()
    assert len(completed) == 1
    assert completed[0].client_ip == "192.168.1.5"
