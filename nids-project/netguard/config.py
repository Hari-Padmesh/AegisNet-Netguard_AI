"""
netguard/config.py
------------------
Configuration for the embeddable NetGuard SDK.

Settings can be passed to NetGuard(...) or loaded from environment variables
prefixed with NETGUARD_.
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DashboardMode(str, Enum):
    EMBEDDED = "embedded"
    SEPARATE = "separate"
    BOTH = "both"


DEFAULT_RULE_COOLDOWNS = {
    "http.sqli": 30.0,
    "http.xss": 30.0,
    "http.path_traversal": 30.0,
    "http.failed_auth_burst": 60.0,
    "http.sensitive_path_scan": 60.0,
    "http.request_burst": 30.0,
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class NetGuardConfig:
    """
    Runtime configuration for NetGuard SDK integrations.

    SMTP email delivery:
        NETGUARD_EMAIL_PROVIDER=smtp
        NETGUARD_SMTP_HOST=smtp.gmail.com
        NETGUARD_SMTP_PORT=587
        NETGUARD_SMTP_USER=you@gmail.com
        NETGUARD_SMTP_PASSWORD=<app-password>
        NETGUARD_SMTP_FROM=you@gmail.com
        NETGUARD_ALERT_EMAIL=owner@gmail.com

    Resend HTTPS API delivery (use when SMTP egress is unavailable):
        NETGUARD_EMAIL_PROVIDER=resend
        NETGUARD_RESEND_API_KEY=<api-key>
        NETGUARD_RESEND_FROM=onboarding@resend.dev
        NETGUARD_ALERT_EMAIL=owner@gmail.com

    Centralized dashboard ingestion:
        NETGUARD_DASHBOARD_MODE=separate
        NETGUARD_DASHBOARD_URL=https://dashboard-api.example.com
        NETGUARD_PROJECT_ID=<registered-project-id>
        NETGUARD_INGEST_KEY=<project-ingestion-key>
    """

    project_id: str = "default"
    model_dir: str = "models"

    # Flow aggregation
    flow_window_seconds: float = 30.0
    min_alert_severity: str = "LOW"

    # Dashboard
    dashboard_mode: DashboardMode = DashboardMode.EMBEDDED
    dashboard_port: int = 8787
    dashboard_url: str = "http://localhost:8787"
    dashboard_path: str = "/netguard"

    # Authentication (required for dashboard/API access)
    auth_username: str = ""
    auth_password: str = ""
    auth_api_key: str = ""
    # Credential used only when forwarding data to the NetGuard cloud dashboard.
    ingest_key: str = ""

    # Alert channels
    alert_email: str = ""
    email_provider: str = "smtp"
    resend_api_key: str = ""
    resend_from: str = "onboarding@resend.dev"
    webhook_url: str = ""
    slack_webhook_url: str = ""

    # Gmail / SMTP
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    # Email cadence
    weekly_digest_enabled: bool = True
    weekly_digest_day: str = "sun"
    weekly_digest_hour: int = 9

    # Detection
    attack_confidence_threshold: float = 0.60
    rule_cooldowns: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_RULE_COOLDOWNS))

    # Logging
    log_file: Optional[str] = "alerts.log"
    console_alerts: bool = True

    @classmethod
    def from_env(cls, **overrides) -> "NetGuardConfig":
        """Build config from NETGUARD_* environment variables with optional overrides."""
        rule_cooldowns = dict(DEFAULT_RULE_COOLDOWNS)
        cooldowns_raw = os.getenv("NETGUARD_RULE_COOLDOWNS", "").strip()
        if cooldowns_raw:
            try:
                cooldown_overrides = json.loads(cooldowns_raw)
                if not isinstance(cooldown_overrides, dict):
                    raise ValueError("NETGUARD_RULE_COOLDOWNS must be a JSON object")
                for rule_id, seconds in cooldown_overrides.items():
                    seconds = float(seconds)
                    if seconds < 0:
                        raise ValueError("Rule cooldowns must be non-negative")
                    rule_cooldowns[str(rule_id)] = seconds
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("NETGUARD_RULE_COOLDOWNS must be a JSON object of seconds") from exc
        mode_raw = os.getenv("NETGUARD_DASHBOARD_MODE", "embedded").lower()
        try:
            dashboard_mode = DashboardMode(mode_raw)
        except ValueError:
            dashboard_mode = DashboardMode.EMBEDDED

        cfg = cls(
            project_id=os.getenv("NETGUARD_PROJECT_ID", "default"),
            model_dir=os.getenv("NETGUARD_MODEL_DIR", "models"),
            flow_window_seconds=float(os.getenv("NETGUARD_FLOW_WINDOW_SECONDS", "30")),
            min_alert_severity=os.getenv("NETGUARD_MIN_ALERT_SEVERITY", "LOW"),
            dashboard_mode=dashboard_mode,
            dashboard_port=int(os.getenv("NETGUARD_DASHBOARD_PORT", "8787")),
            dashboard_url=os.getenv("NETGUARD_DASHBOARD_URL", "http://localhost:8787"),
            dashboard_path=os.getenv("NETGUARD_DASHBOARD_PATH", "/netguard"),
            auth_username=os.getenv("NETGUARD_AUTH_USERNAME", ""),
            auth_password=os.getenv("NETGUARD_AUTH_PASSWORD", ""),
            auth_api_key=os.getenv("NETGUARD_AUTH_API_KEY", ""),
            ingest_key=os.getenv("NETGUARD_INGEST_KEY", ""),
            alert_email=os.getenv("NETGUARD_ALERT_EMAIL", ""),
            email_provider=os.getenv("NETGUARD_EMAIL_PROVIDER", "smtp").strip().lower(),
            resend_api_key=os.getenv("NETGUARD_RESEND_API_KEY", ""),
            resend_from=os.getenv("NETGUARD_RESEND_FROM", "onboarding@resend.dev"),
            webhook_url=os.getenv("NETGUARD_WEBHOOK_URL", ""),
            slack_webhook_url=os.getenv("NETGUARD_SLACK_WEBHOOK", ""),
            smtp_host=os.getenv("NETGUARD_SMTP_HOST", "smtp.gmail.com"),
            smtp_port=int(os.getenv("NETGUARD_SMTP_PORT", "587")),
            smtp_user=os.getenv("NETGUARD_SMTP_USER", ""),
            smtp_password=os.getenv("NETGUARD_SMTP_PASSWORD", ""),
            smtp_from=os.getenv("NETGUARD_SMTP_FROM", os.getenv("NETGUARD_SMTP_USER", "")),
            smtp_use_tls=_env_bool("NETGUARD_SMTP_USE_TLS", True),
            weekly_digest_enabled=_env_bool("NETGUARD_WEEKLY_DIGEST_ENABLED", True),
            weekly_digest_day=os.getenv("NETGUARD_WEEKLY_DIGEST_DAY", "sun"),
            weekly_digest_hour=int(os.getenv("NETGUARD_WEEKLY_DIGEST_HOUR", "9")),
            attack_confidence_threshold=float(
                os.getenv("NETGUARD_ATTACK_CONFIDENCE_THRESHOLD", "0.60")
            ),
            rule_cooldowns=rule_cooldowns,
            log_file=os.getenv("NETGUARD_LOG_FILE", "alerts.log"),
            console_alerts=_env_bool("NETGUARD_CONSOLE_ALERTS", True),
        )
        for key, value in overrides.items():
            if hasattr(cfg, key) and value is not None:
                if key == "dashboard_mode" and isinstance(value, str):
                    value = DashboardMode(value.lower())
                setattr(cfg, key, value)
        return cfg

    def validate_auth(self) -> None:
        """
        Ensure dashboard authentication is configured.

        Raises
        ------
        ValueError if neither API key nor username/password is set.
        """
        has_basic = bool(self.auth_username and self.auth_password)
        has_api_key = bool(self.auth_api_key)
        if not has_basic and not has_api_key:
            raise ValueError(
                "NetGuard dashboard authentication is required. Set either "
                "NETGUARD_AUTH_USERNAME + NETGUARD_AUTH_PASSWORD or NETGUARD_AUTH_API_KEY."
            )

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_password and self.alert_email)

    @property
    def resend_configured(self) -> bool:
        return bool(self.resend_api_key and self.resend_from and self.alert_email)

    @property
    def email_configured(self) -> bool:
        provider = self.email_provider.strip().lower()
        if provider == "resend":
            return self.resend_configured
        if provider == "smtp":
            return self.smtp_configured
        return False
