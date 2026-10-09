"""
tests/test_integrations.py
--------------------------
Unit tests for the NetGuard In-App SDK, FastAPI middleware,
traffic monitor, webhook notifiers, and dashboard endpoints.
"""

import pytest
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from netguard.detection import DetectionEngine, PredictionResult
from netguard.alerts import AlertManager, Alert, Severity
from netguard import NetGuard
from netguard.integrations.base import AppTrafficMonitor
from netguard.integrations.fastapi import NetGuardMiddleware, setup_netguard
from netguard.notifier.webhook import WebhookNotifier


class TestBundledModelLoading:
    def test_default_load_succeeds_without_arguments(self):
        """DetectionEngine should load bundled package models without needing model_dir."""
        engine = DetectionEngine().load()
        assert engine.is_loaded
        assert "BENIGN" in engine.classes
        assert len(engine.features) == 20


class TestAppTrafficMonitor:
    def test_benign_request_analysis(self):
        """Standard request should be evaluated as benign."""
        monitor = AppTrafficMonitor()
        result = monitor.analyze_request(
            client_ip="192.168.1.50",
            client_port=54321,
            server_port=80,
            method="GET",
            path="/api/items",
            query_string="",
            headers={"host": "localhost", "content-length": "0"},
            request_bytes=0,
            response_bytes=150,
            status_code=200,
            duration=0.015,
        )
        assert isinstance(result, PredictionResult)
        stats = monitor.get_stats()
        assert stats["total_requests"] == 1
        assert stats["total_attacks"] == 0

    def test_sqli_attack_detection(self):
        """SQL injection query should be flagged as an attack."""
        monitor = AppTrafficMonitor()
        result = monitor.analyze_request(
            client_ip="10.0.0.99",
            client_port=44444,
            server_port=80,
            method="GET",
            path="/search",
            query_string="q=1' UNION SELECT password FROM users --",
            headers={"host": "localhost"},
            request_bytes=0,
            response_bytes=500,
            status_code=200,
            duration=0.02,
        )
        assert result.is_attack
        assert "Sql Injection" in result.label
        stats = monitor.get_stats()
        assert stats["total_attacks"] == 1

    def test_xss_attack_detection(self):
        """XSS query should be flagged as an attack."""
        monitor = AppTrafficMonitor()
        result = monitor.analyze_request(
            client_ip="10.0.0.101",
            client_port=44445,
            server_port=80,
            method="GET",
            path="/comment",
            query_string="text=<script>alert('xss')</script>",
            headers={"host": "localhost"},
            request_bytes=0,
            response_bytes=300,
            status_code=200,
            duration=0.01,
        )
        assert result.is_attack
        assert "XSS" in result.label

    def test_manual_ip_block_and_unblock(self):
        """IP blocking and unblocking should work predictably."""
        monitor = AppTrafficMonitor()
        ip = "198.51.100.22"

        assert not monitor.is_ip_blocked(ip)
        monitor.block_ip(ip, duration=60.0)
        assert monitor.is_ip_blocked(ip)

        blocked = monitor.get_blocked_ips()
        assert ip in blocked

        monitor.unblock_ip(ip)
        assert not monitor.is_ip_blocked(ip)


class TestFastAPIMiddleware:
    @staticmethod
    def _build_app(**guard_options):
        app = FastAPI()
        config = {
            "project_id": "test-app",
            "auth_username": "admin",
            "auth_password": "secret",
        }
        config.update(guard_options)
        guard = NetGuard(**config)
        setup_netguard(app, guard)

        @app.get("/")
        async def home():
            return {"status": "ok"}

        return app, guard

    def test_middleware_attaches_and_intercepts(self):
        """FastAPI middleware should process requests and record request counts."""
        app, guard = self._build_app()

        client = TestClient(app)

        resp = client.get("/")
        assert resp.status_code == 200
        assert guard.request_count == 1

    def test_health_requires_basic_auth(self):
        """The Phase 1 health endpoint should require configured credentials."""
        app, _ = self._build_app()
        client = TestClient(app)

        unauthorized = client.get("/netguard/health")
        authorized = client.get("/netguard/health", auth=("admin", "secret"))

        assert unauthorized.status_code == 401
        assert authorized.status_code == 200
        assert authorized.json()["status"] == "ok"

    def test_health_accepts_bearer_api_key(self):
        """The Phase 1 health endpoint should accept a configured API key."""
        app, _ = self._build_app(auth_username="", auth_password="", auth_api_key="test-key")
        client = TestClient(app)

        response = client.get(
            "/netguard/health",
            headers={"Authorization": "Bearer test-key"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_dashboard_routes_are_authenticated(self):
        """Embedded dashboard HTML and APIs require the configured credentials."""
        app, _ = self._build_app()
        client = TestClient(app)

        assert client.get("/netguard/").status_code == 401
        dashboard = client.get("/netguard/", auth=("admin", "secret"))
        stats = client.get("/netguard/api/stats", auth=("admin", "secret"))

        assert dashboard.status_code == 200
        assert "NetGuard AI" in dashboard.text
        assert stats.status_code == 200
        assert stats.json()["project_id"] == "test-app"

    def test_dashboard_block_ip_action_updates_core_state(self):
        """Authenticated dashboard block actions should update the core."""
        app, guard = self._build_app()
        client = TestClient(app)

        blocked = client.post(
            "/netguard/api/block-ip",
            auth=("admin", "secret"),
            json={"ip": "198.51.100.40", "action": "block"},
        )
        unblocked = client.post(
            "/netguard/api/block-ip",
            auth=("admin", "secret"),
            json={"ip": "198.51.100.40", "action": "unblock"},
        )

        assert blocked.json()["status"] == "blocked"
        assert guard.is_ip_blocked("198.51.100.40") is False
        assert unblocked.json()["status"] == "unblocked"

    def test_dashboard_websocket_requires_authentication(self):
        """Dashboard telemetry should reject unauthenticated WebSocket clients."""
        app, _ = self._build_app()
        client = TestClient(app)

        with pytest.raises(Exception):
            with client.websocket_connect("/netguard/ws") as websocket:
                websocket.receive_text()

    def test_dashboard_websocket_streams_telemetry(self):
        """Authenticated WebSocket clients should receive telemetry messages."""
        app, _ = self._build_app()
        client = TestClient(app)

        with client.websocket_connect("/netguard/ws", headers={"authorization": "Basic YWRtaW46c2VjcmV0"}) as websocket:
            message = websocket.receive_json()

        assert message["type"] == "telemetry"
        assert message["data"]["project_id"] == "test-app"

    def test_dashboard_accepts_authenticated_remote_event(self):
        """Standalone dashboard event ingestion should create an alert."""
        app, guard = self._build_app()
        client = TestClient(app)

        response = client.post(
            "/netguard/api/events",
            auth=("admin", "secret"),
            json={
                "label": "PortScan",
                "confidence": 0.95,
                "flow_summary": "remote test event",
                "detection_source": "remote",
            },
        )

        assert response.status_code == 200
        assert response.json()["accepted"] is True
        assert guard.alert_manager.stats()["total"] == 1


class TestWebhookNotifier:
    def test_generic_webhook_payload_structure(self):
        """WebhookNotifier should build well-formatted payloads."""
        notifier = WebhookNotifier(url="https://example.com/webhook", service="generic")
        alert = Alert(
            timestamp="2026-09-14T23:00:00Z",
            severity=Severity.HIGH,
            label="DDoS",
            confidence=0.95,
            flow_summary="10.0.0.1 -> :80 | Flood",
        )
        payload = notifier._build_generic_payload(alert)
        assert payload["event"] == "NETGUARD_ATTACK_ALERT"
        assert payload["attack_type"] == "DDoS"
        assert payload["confidence"] == 0.95

    def test_discord_payload_structure(self):
        """Discord webhook formatting should contain embeds."""
        notifier = WebhookNotifier(url="https://discord.com/api/webhooks/123/abc", service="discord")
        alert = Alert(
            timestamp="2026-09-14T23:00:00Z",
            severity=Severity.CRITICAL,
            label="Botnet",
            confidence=0.99,
            flow_summary="10.0.0.5 -> :443",
        )
        payload = notifier._build_discord_payload(alert)
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1
        assert "Botnet" in payload["embeds"][0]["description"]

    def test_cooldown_throttling(self):
        """Duplicate alerts within cooldown period should be throttled."""
        notifier = WebhookNotifier(url="https://example.com/webhook", cooldown_seconds=5.0)
        alert = Alert(
            timestamp="2026-09-14T23:00:00Z",
            severity=Severity.HIGH,
            label="PortScan",
            confidence=0.88,
            flow_summary="Test",
        )

        assert notifier.should_send(alert) is True
        # Immediately sending the same alert type should be throttled
        assert notifier.should_send(alert) is False
