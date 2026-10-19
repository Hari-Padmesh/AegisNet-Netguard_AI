"""Tests for the canonical embeddable NetGuard core."""

from unittest.mock import patch

from netguard.core import NetGuard
from netguard.notifier.dashboard import DashboardEventNotifier


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


def test_steady_requests_do_not_trigger_burst_rule():
    guard = build_guard()

    results = []
    for timestamp in [index * 0.2 for index in range(25)]:
        guard._rules.evaluate(
            client_ip="198.51.100.14",
            path="/api/items",
            now=timestamp,
        )
        results.append(guard._rules.evaluate(
            client_ip="198.51.100.15",
            path="/api/items",
            now=timestamp,
        ))

    assert all(result is None for result in results)


def test_forbidden_product_requests_do_not_look_like_brute_force():
    guard = build_guard()

    results = []
    for _ in range(10):
        results.append(
            guard.process_request(
                client_ip="198.51.100.16",
                req_bytes=32,
                resp_bytes=0,
                path="/api/products",
                status_code=403,
            )
        )

    assert all(not any(result.label == "BruteForce" for result in batch) for batch in results)


def test_stats_include_benign_request_events():
    guard = build_guard()
    guard.process_request(
        client_ip="198.51.100.17",
        req_bytes=32,
        resp_bytes=128,
        path="/api/products",
    )

    events = guard.stats()["recent_events"]
    assert events[-1]["label"] == "BENIGN"
    assert events[-1]["path"] == "/api/products"


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


def test_rule_alert_cooldown_suppresses_repeats_but_keeps_events():
    guard = build_guard(rule_cooldowns={"http.sqli": 10.0})

    def send(timestamp):
        return guard.process_request(
            client_ip="198.51.100.20",
            req_bytes=64,
            resp_bytes=128,
            path="/search",
            query_string="q=UNION SELECT password",
            timestamp=timestamp,
        )

    send(100.0)
    send(101.0)

    assert len(guard.alert_manager.history) == 1
    assert guard.stats()["suppressed_alerts"] == 1
    assert guard.stats()["recent_events"][-1]["label"] == "Web Attack - Sql Injection"
    assert guard.stats()["recent_events"][-1]["alert_suppressed"] is True

    send(111.0)
    assert len(guard.alert_manager.history) == 2


def test_rule_cooldown_is_scoped_to_client():
    guard = build_guard(rule_cooldowns={"http.sqli": 60.0})
    for client_ip in ("198.51.100.21", "198.51.100.22"):
        guard.process_request(
            client_ip=client_ip,
            req_bytes=64,
            resp_bytes=128,
            path="/search",
            query_string="q=UNION SELECT password",
            timestamp=100.0,
        )

    assert len(guard.alert_manager.history) == 2
    assert guard.stats()["suppressed_alerts"] == 0


def test_separate_dashboard_receives_request_telemetry():
    guard = build_guard(dashboard_mode="separate", dashboard_url="http://dashboard.test")

    with patch.object(DashboardEventNotifier, "notify_telemetry") as publish:
        guard.process_request(
            client_ip="198.51.100.30",
            req_bytes=32,
            resp_bytes=64,
            path="/api/items",
        )

    snapshot = publish.call_args.args[0]
    assert snapshot["total_requests"] == 1
    assert snapshot["top_clients"][0]["ip"] == "198.51.100.30"
