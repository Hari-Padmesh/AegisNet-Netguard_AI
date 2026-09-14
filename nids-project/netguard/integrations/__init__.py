"""
netguard/integrations
---------------------
In-App framework middleware and integrations (FastAPI, Starlette, Flask, etc.)
"""

from netguard.integrations.base import AppTrafficMonitor
from netguard.integrations.fastapi import NetGuardMiddleware, NetGuard

__all__ = ["AppTrafficMonitor", "NetGuardMiddleware", "NetGuard"]
