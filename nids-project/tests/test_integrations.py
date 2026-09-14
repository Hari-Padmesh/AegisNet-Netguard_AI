"""
tests/test_integrations.py
--------------------------
Unit tests for the NetGuard In-App SDK, FastAPI middleware,
traffic monitor, webhook notifiers, and dashboard endpoints.
"""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from netguard.detection import DetectionEngine, PredictionResult
from netguard.alerts import AlertManager, Alert, Severity
from netguard.integrations.base import AppTrafficMonitor
from netguard.integrations.fastapi import NetGuardMiddleware, NetGuard
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
    def test_middleware_attaches_and_intercepts(self):
        """Starlette / FastAPI app protected by NetGuard should process requests and record stats."""
        async def home(request):
            return PlainTextResponse("Hello Secure World")

        app = Starlette(routes=[Route("/", endpoint=home)])
        guard = NetGuard(app, dashboard=True, mount_path="/_netguard")

        client = TestClient(app)

        # Normal request
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.text == "Hello Secure World"

        # Check that request was recorded
        stats = guard.get_stats()
        assert stats["total_requests"] >= 1

    def test_dashboard_route_serves_html(self):
        """The mounted dashboard endpoint should serve the HTML dashboard."""
        async def home(request):
            return PlainTextResponse("Home")

        app = Starlette(routes=[Route("/", endpoint=home)])
        guard = NetGuard(app, dashboard=True, mount_path="/_netguard")

        client = TestClient(app)
        resp = client.get("/_netguard/")
        assert resp.status_code == 200
        assert "NetGuard AI" in resp.text
        assert "System Threat Level" in resp.text or "SYSTEM THREAT LEVEL" in resp.text

    def test_dashboard_api_stats_endpoint(self):
        """Dashboard API stats endpoint should return telemetry JSON."""
        async def home(request):
            return PlainTextResponse("Home")

        app = Starlette(routes=[Route("/", endpoint=home)])
        guard = NetGuard(app, dashboard=True, mount_path="/_netguard")

        client = TestClient(app)
        resp = client.get("/_netguard/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "threat_level" in data

    def test_auto_blocking_returns_403(self):
        """When an IP is blocked, requests should receive 403 Forbidden."""
        async def home(request):
            return PlainTextResponse("Home")

        app = Starlette(routes=[Route("/", endpoint=home)])
        guard = NetGuard(app, dashboard=True, mount_path="/_netguard", block_attacks=True)

        client = TestClient(app)

        # Block IP
        guard.block_ip("testclient")

        resp = client.get("/")
        assert resp.status_code == 403
        assert "blocked" in resp.text.lower()


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
