"""Tests for the canonical embeddable NetGuard core."""

from netguard.core import NetGuard


def build_guard(**overrides) -> NetGuard:
    options = {
        "project_id": "test-app",
        "auth_username": "admin",
        "auth_password": "secret",
        "log_file": None,
        "console_alerts": False,
    }
    options.update(overrides)
    return NetGuard(**options)


def test_sql_injection_rule_alerts_immediately():
    guard = build_guard()

    results = guard.process_request(
        client_ip="198.51.100.10",
        req_bytes=64,
        resp_bytes=128,
        path="/search",
        query_string="q=1' UNION SELECT password FROM users --",
    )

    assert len(results) == 1
    assert results[0].detection_source == "rule"
    assert results[0].label == "Web Attack - Sql Injection"
    assert guard.stats()["attacks"] == 1
    assert guard.stats()["predictions"] == 1


def test_request_burst_rule_alerts_after_threshold():
    guard = build_guard()

    results = []
    for _ in range(25):
        results = guard.process_request(
            client_ip="198.51.100.11",
            req_bytes=32,
            resp_bytes=64,
            path="/api/items",
        )

    assert results
    assert results[-1].label == "DoS"
    assert results[-1].detection_source == "rule"
    assert guard.stats()["attacks"] >= 1


def test_shutdown_flushes_active_flow_and_updates_telemetry():
    guard = build_guard()

    guard.process_request(
        client_ip="198.51.100.12",
        req_bytes=32,
        resp_bytes=128,
        path="/api/items",
    )

    before = guard.stats()
    assert before["active_flows"] == 1
    assert before["flows_scored"] == 0

    results = guard.shutdown()

    after = guard.stats()
    assert len(results) == 1
    assert after["active_flows"] == 0
    assert after["flows_scored"] == 1
    assert after["predictions"] == 1


def test_registered_notifier_receives_rule_alert():
    guard = build_guard()
    received = []

    class Recorder:
        def notify(self, alert):
            received.append(alert)

    guard.register_notifier(Recorder())
    guard.process_request(
        client_ip="198.51.100.13",
        req_bytes=64,
        resp_bytes=128,
        path="/search",
        query_string="q=<script>alert(1)</script>",
    )

    assert len(received) == 1
    assert received[0].detection_source == "rule"