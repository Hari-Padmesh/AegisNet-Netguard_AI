"""
netguard/integrations/flask.py
------------------------------
Flask extension for NetGuard AI.

Usage:
    from flask import Flask
    from netguard.integrations.flask import NetGuardFlask

    app = Flask(__name__)
    guard = NetGuardFlask(app, dashboard=True, alert_webhook="https://...")
"""

import os
import time
from typing import Optional, Dict, Any

from netguard.detection import DetectionEngine
from netguard.alerts import AlertManager
from netguard.integrations.base import AppTrafficMonitor


class NetGuardFlask:
    """
    Flask extension providing real-time in-app threat defense and dashboard.
    """

    def __init__(
        self,
        app: Optional[Any] = None,
        dashboard: bool = True,
        mount_path: str = "/_netguard",
        alert_webhook: Optional[str] = None,
        alert_log_file: Optional[str] = None,
        block_attacks: bool = False,
        block_duration_seconds: float = 300.0,
        engine: Optional[DetectionEngine] = None,
    ):
        self.dashboard = dashboard
        self.mount_path = mount_path.rstrip("/")
        self.block_attacks = block_attacks
        self.block_duration_seconds = block_duration_seconds

        self.alert_manager = AlertManager(
            log_file=alert_log_file,
            console_output=False,
            webhook_url=alert_webhook,
        )

        self.monitor = AppTrafficMonitor(
            engine=engine,
            alert_manager=self.alert_manager,
            block_attacks=block_attacks,
            block_duration_seconds=block_duration_seconds,
        )

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        try:
            from flask import request, abort, Response, jsonify
        except ImportError:
            raise ImportError("Flask is not installed. Install via: pip install flask")

        clean_mount = self.mount_path

        @app.before_request
        def netguard_before_request():
            # Bypass dashboard paths
            if request.path.startswith(clean_mount):
                return None

            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
            if "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()

            if self.monitor.is_ip_blocked(client_ip):
                abort(403, description="Blocked by NetGuard AI threat protection.")

            request._netguard_start_time = time.time()

        @app.after_request
        def netguard_after_request(response: Response):
            if request.path.startswith(clean_mount):
                return response

            start_time = getattr(request, "_netguard_start_time", time.time())
            duration = time.time() - start_time

            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
            if "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()

            request_bytes = int(request.headers.get("Content-Length", 0))
            response_bytes = int(response.headers.get("Content-Length", len(response.data) if hasattr(response, 'data') else 0))

            self.monitor.analyze_request(
                client_ip=client_ip,
                client_port=0,
                server_port=request.environ.get("SERVER_PORT", 80),
                method=request.method,
                path=request.path,
                query_string=request.query_string.decode("utf-8", errors="ignore"),
                headers=dict(request.headers),
                request_bytes=request_bytes,
                response_bytes=response_bytes,
                status_code=response.status_code,
                duration=duration,
            )

            return response

        if self.dashboard:
            html_path = os.path.join(os.path.dirname(__file__), "..", "web", "static", "dashboard.html")

            @app.route(f"{clean_mount}", methods=["GET"])
            @app.route(f"{clean_mount}/", methods=["GET"])
            def netguard_dashboard():
                if os.path.exists(html_path):
                    with open(html_path, "r", encoding="utf-8") as f:
                        return Response(f.read(), mimetype="text/html")
                return "Dashboard HTML not found", 404

            @app.route(f"{clean_mount}/api/stats", methods=["GET"])
            def netguard_api_stats():
                return jsonify(self.monitor.get_stats())

            @app.route(f"{clean_mount}/api/alerts", methods=["GET"])
            def netguard_api_alerts():
                history = [a.to_dict() for a in self.monitor.alert_manager.history[-50:]]
                return jsonify({"alerts": history})

            @app.route(f"{clean_mount}/api/block-ip", methods=["POST"])
            def netguard_api_block():
                data = request.get_json(silent=True) or {}
                ip = data.get("ip")
                action = data.get("action", "block")
                if not ip:
                    return jsonify({"error": "Missing IP"}), 400
                if action == "unblock":
                    self.monitor.unblock_ip(ip)
                    return jsonify({"status": "unblocked", "ip": ip})
                else:
                    self.monitor.block_ip(ip)
                    return jsonify({"status": "blocked", "ip": ip})
