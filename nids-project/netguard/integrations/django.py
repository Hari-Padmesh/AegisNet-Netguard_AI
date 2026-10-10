"""Optional Django middleware for the NetGuard application SDK."""

from __future__ import annotations

import time
from typing import Optional

from netguard.core import NetGuard


def _client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


class NetGuardDjangoMiddleware:
    """Django request middleware backed by a shared NetGuard instance.

    Configure it in ``MIDDLEWARE``. Pass a guard explicitly in tests or set
    ``NETGUARD_*`` environment variables before Django initializes.
    """

    def __init__(self, get_response, guard: Optional[NetGuard] = None):
        self.get_response = get_response
        self.guard = guard or NetGuard()

    def __call__(self, request):
        try:
            from django.http import HttpResponseForbidden
        except ImportError as exc:
            raise ImportError("Django integration requires: pip install 'netguard[web]'") from exc

        client_ip = _client_ip(request)
        if self.guard.is_ip_blocked(client_ip):
            return HttpResponseForbidden("Blocked by NetGuard threat protection.")

        started = time.perf_counter()
        response = self.get_response(request)
        request_bytes = int(request.META.get("CONTENT_LENGTH") or 0)
        response_bytes = len(getattr(response, "content", b""))

        self.guard.process_request(
            client_ip=client_ip,
            req_bytes=request_bytes,
            resp_bytes=response_bytes,
            dest_port=int(request.META.get("SERVER_PORT") or 80),
            path=request.path,
            method=request.method,
            query_string=request.META.get("QUERY_STRING", ""),
            status_code=response.status_code,
        )
        response["X-NetGuard-Processing-Ms"] = f"{(time.perf_counter() - started) * 1000:.2f}"
        return response