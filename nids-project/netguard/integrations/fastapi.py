"""
netguard/integrations/fastapi.py
--------------------------------
FastAPI middleware and setup helper for NetGuard SDK.
"""

from __future__ import annotations

from typing import Callable, Optional

from netguard.aggregator import HttpFlowAggregator
from netguard.core import NetGuard


def _client_ip_from_request(request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _request_body_size(request) -> float:
    length = request.headers.get("content-length")
    if length and length.isdigit():
        return float(length)
    return 0.0


class NetGuardMiddleware:
    """
    ASGI middleware that records HTTP traffic and runs ML classification.

    Install with setup_netguard(app, guard) or add directly:
        app.add_middleware(NetGuardMiddleware, guard=guard)
    """

    def __init__(self, app, guard: NetGuard):
        self.app = app
        self.guard = guard

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        dashboard_path = self.guard.config.dashboard_path.rstrip("/")
        request_path = scope.get("path", "/")
        if dashboard_path and (
            request_path == dashboard_path
            or request_path.startswith(f"{dashboard_path}/")
        ):
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request

        request = Request(scope, receive)
        client_ip = _client_ip_from_request(request)
        req_bytes = _request_body_size(request)
        dest_port = HttpFlowAggregator.dest_port_from_request(
            request.headers.get("host"),
            scheme=scope.get("scheme", "http"),
        )
        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        query_string = scope.get("query_string", b"").decode("utf-8", errors="replace")

        resp_bytes = 0.0
        status_code = 200

        async def send_wrapper(message):
            nonlocal resp_bytes, status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                resp_bytes += len(body)
            await send(message)

        await self.app(scope, receive, send_wrapper)

        # Approximate response size from status when body was empty (e.g. 204)
        if resp_bytes == 0 and status_code not in (204, 304):
            resp_bytes = 256.0

        self.guard.process_request(
            client_ip=client_ip,
            req_bytes=req_bytes,
            resp_bytes=resp_bytes,
            dest_port=dest_port,
            path=path,
            method=method,
            query_string=query_string,
            status_code=status_code,
        )


def setup_netguard(app, guard: NetGuard, mount_dashboard: bool = True) -> NetGuard:
    """
    Attach NetGuard to a FastAPI application.

    Parameters
    ----------
    app : FastAPI
        The host application.
    guard : NetGuard
        Configured NetGuard instance.
    mount_dashboard : bool
        When True, mount the authenticated dashboard under the configured path.

    Returns
    -------
    NetGuard
        The same guard instance for chaining.
    """
    app.add_middleware(NetGuardMiddleware, guard=guard)

    @app.on_event("shutdown")
    async def _netguard_shutdown():
        guard.shutdown()

    base_path = guard.config.dashboard_path.rstrip("/")

    if mount_dashboard:
        from netguard.web.app import create_dashboard_app

        app.mount(base_path, create_dashboard_app(guard))
    else:
        from fastapi import Depends
        from netguard.auth import create_fastapi_auth_dependency

        require_auth = create_fastapi_auth_dependency(guard.config)

        @app.get(f"{base_path}/health")
        async def netguard_health(_user: str = Depends(require_auth)):
            return {"status": "ok", **guard.stats()}

    return guard
