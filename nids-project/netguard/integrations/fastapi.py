"""
netguard/integrations/fastapi.py
--------------------------------
FastAPI / Starlette ASGI Middleware and Integrator for NetGuard AI.

Usage:
    from fastapi import FastAPI
    from netguard.integrations.fastapi import NetGuardMiddleware

    app = FastAPI()
    app.add_middleware(
        NetGuardMiddleware,
        dashboard=True,
        mount_path="/_netguard",
        alert_webhook="https://discord.com/api/webhooks/...",
        block_attacks=True,
    )
"""

import time
from typing import Optional, Dict, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from netguard.detection import DetectionEngine
from netguard.alerts import AlertManager, Severity
from netguard.integrations.base import AppTrafficMonitor
from netguard.web.app import create_dashboard_app


class NetGuardMiddleware(BaseHTTPMiddleware):
    """
    Asynchronous ASGI Middleware for FastAPI / Starlette applications.
    Inspects inbound and outbound application traffic in real time with zero admin privileges.

    Parameters
    ----------
    app : ASGIApp
        The Starlette / FastAPI application.
    dashboard : bool
        Whether to mount the real-time web dashboard (default True).
    mount_path : str
        URL path where the dashboard is mounted (default "/_netguard").
    alert_webhook : str, optional
        Webhook URL (Discord, Slack, or generic HTTP POST) for instant alert notifications.
    alert_log_file : str, optional
        Path to JSON-lines alert audit log file.
    block_attacks : bool
        Whether to automatically block IPs identified in high-confidence attacks (default False).
    block_duration_seconds : float
        Duration to block offending client IPs (default 300s).
    engine : DetectionEngine, optional
        Custom DetectionEngine instance (defaults to pre-trained bundled model).
    """

    def __init__(
        self,
        app: ASGIApp,
        dashboard: bool = True,
        mount_path: str = "/_netguard",
        alert_webhook: Optional[str] = None,
        alert_log_file: Optional[str] = None,
        block_attacks: bool = False,
        block_duration_seconds: float = 300.0,
        engine: Optional[DetectionEngine] = None,
        monitor: Optional[AppTrafficMonitor] = None,
    ):
        super().__init__(app)
        self.mount_path = mount_path.rstrip("/")
        self.dashboard_enabled = dashboard

        if monitor is not None:
            self.monitor = monitor
            self.alert_manager = monitor.alert_manager
        else:
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

        # Create dashboard app
        self._dashboard_app = create_dashboard_app(self.monitor) if dashboard else None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # 1. If requesting dashboard route, let dashboard handle it without threat scoring
        if self.dashboard_enabled and (path == self.mount_path or path.startswith(self.mount_path + "/")):
            return await call_next(request)

        # 2. Extract client IP
        client_ip = request.headers.get("x-forwarded-for")
        if client_ip:
            client_ip = client_ip.split(",")[0].strip()
        elif request.client and request.client.host:
            client_ip = request.client.host
        else:
            client_ip = "127.0.0.1"

        client_port = request.client.port if request.client else 0
        server_port = request.url.port or (443 if request.url.scheme == "https" else 80)

        # 3. Check if IP is actively blocked
        if self.monitor.is_ip_blocked(client_ip):
            return JSONResponse(
                {
                    "error": "Access Denied",
                    "detail": "Your IP address has been temporarily blocked by NetGuard AI threat protection."
                },
                status_code=403,
            )

        # 4. Measure request payload length
        request_bytes = int(request.headers.get("content-length", 0))

        # 5. Process request through downstream application
        start_time = time.time()
        try:
            response = await call_next(request)
            status_code = response.status_code
            response_bytes = int(response.headers.get("content-length", 0))
        except Exception as exc:
            status_code = 500
            response_bytes = 0
            raise exc
        finally:
            duration = time.time() - start_time

            # 6. Analyze request asynchronously in traffic monitor
            self.monitor.analyze_request(
                client_ip=client_ip,
                client_port=client_port,
                server_port=server_port,
                method=request.method,
                path=path,
                query_string=request.url.query,
                headers=dict(request.headers),
                request_bytes=request_bytes,
                response_bytes=response_bytes,
                status_code=status_code,
                duration=duration,
            )

        return response


def NetGuard(
    app: Any,
    dashboard: bool = True,
    mount_path: str = "/_netguard",
    alert_webhook: Optional[str] = None,
    alert_log_file: Optional[str] = None,
    block_attacks: bool = False,
    block_duration_seconds: float = 300.0,
    engine: Optional[DetectionEngine] = None,
) -> AppTrafficMonitor:
    """
    Convenience helper to attach NetGuard protection and dashboard to a FastAPI app.

    Usage:
        app = FastAPI()
        guard = NetGuard(app, dashboard=True, alert_webhook="https://...")
    """
    # Create the monitor
    alert_mgr = AlertManager(
        log_file=alert_log_file,
        console_output=False,
        webhook_url=alert_webhook,
    )
    monitor = AppTrafficMonitor(
        engine=engine,
        alert_manager=alert_mgr,
        block_attacks=block_attacks,
        block_duration_seconds=block_duration_seconds,
    )

    # Mount dashboard sub-app if enabled
    clean_mount = mount_path.rstrip("/")
    if dashboard and hasattr(app, "mount"):
        dash_app = create_dashboard_app(monitor)
        app.mount(clean_mount, dash_app)

    # Add middleware
    app.add_middleware(
        NetGuardMiddleware,
        dashboard=dashboard,
        mount_path=clean_mount,
        alert_webhook=alert_webhook,
        alert_log_file=alert_log_file,
        block_attacks=block_attacks,
        block_duration_seconds=block_duration_seconds,
        engine=engine,
        monitor=monitor,
    )

    return monitor
