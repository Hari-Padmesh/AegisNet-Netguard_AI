"""Tests for external alert delivery without making network connections."""

import threading
from unittest.mock import MagicMock, patch

from netguard.alerts import Alert, Severity
from netguard.config import NetGuardConfig
from netguard.digest import seconds_until_next_digest
from netguard.notifier.email import EmailNotifier
from netguard.notifier.dashboard import DashboardEventNotifier
from netguard.notifier.webhook import WebhookNotifier


def make_alert() -> Alert:
    return Alert(
        timestamp="2026-10-09T12:00:00",
        severity=Severity.HIGH,
        label="PortScan",
        confidence=0.95,
        flow_summary="test flow",
    )


def test_email_notifier_sends_instant_alert_without_real_smtp():
    config = NetGuardConfig(
        project_id="test-app",
        alert_email="owner@example.com",
        smtp_user="sender@example.com",
        smtp_password="app-password",
        smtp_from="sender@example.com",
    )
    smtp = MagicMock()
    threads_started: list[threading.Thread] = []
    original_start = threading.Thread.start

    def track_start(self):
        threads_started.append(self)
        original_start(self)

    with patch("netguard.notifier.email.smtplib.SMTP") as smtp_factory, \
         patch.object(threading.Thread, "start", track_start):
        smtp_factory.return_value.__enter__.return_value = smtp
        EmailNotifier(config, cooldown_seconds=0).notify(make_alert())
        # Join *inside* the patch context so the mock is still live when the thread runs
        for t in threads_started:
            t.join(timeout=5)

    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("sender@example.com", "app-password")
    smtp.send_message.assert_called_once()


def test_email_notifier_sends_digest_without_real_smtp():
    config = NetGuardConfig(
        project_id="test-app",
        alert_email="owner@example.com",
        smtp_user="sender@example.com",
        smtp_password="app-password",
    )
    smtp = MagicMock()
    with patch("netguard.notifier.email.smtplib.SMTP") as smtp_factory:
        smtp_factory.return_value.__enter__.return_value = smtp
        sent = EmailNotifier(config).send_digest([make_alert()])

    assert sent is True
    smtp.send_message.assert_called_once()


def test_email_notifier_cooldown_suppresses_duplicate_label():
    """A second alert for the same label within the cooldown window is not emailed."""
    config = NetGuardConfig(
        project_id="test-app",
        alert_email="owner@example.com",
        smtp_user="sender@example.com",
        smtp_password="app-password",
    )
    smtp = MagicMock()
    threads_started: list[threading.Thread] = []
    original_start = threading.Thread.start

    def track_start(self):
        threads_started.append(self)
        original_start(self)

    notifier = EmailNotifier(config, cooldown_seconds=60.0)
    with patch("netguard.notifier.email.smtplib.SMTP") as smtp_factory, \
         patch.object(threading.Thread, "start", track_start):
        smtp_factory.return_value.__enter__.return_value = smtp
        notifier.notify(make_alert())  # first — should send
        notifier.notify(make_alert())  # second — same label, within cooldown, should be suppressed
        # Join inside the patch so mock is active when threads run
        for t in threads_started:
            t.join(timeout=5)

    # Only one email despite two alerts
    assert smtp.send_message.call_count == 1


def test_webhook_notifier_posts_with_mocked_http():
    notifier = WebhookNotifier("https://example.test/hook", cooldown_seconds=0)
    with patch("netguard.notifier.webhook.requests.post") as post:
        post.return_value.status_code = 204
        notifier.notify(make_alert())

    post.assert_called_once()
    assert post.call_args.kwargs["json"]["attack_type"] == "PortScan"


def test_dashboard_notifier_sends_latest_telemetry_in_background():
    config = NetGuardConfig(
        project_id="test-app",
        dashboard_url="http://dashboard.test",
        auth_username="admin",
        auth_password="secret",
    )
    notifier = DashboardEventNotifier(config)
    delivered = threading.Event()
    response = MagicMock(status_code=200)

    def post(*args, **kwargs):
        delivered.set()
        return response

    with patch("netguard.notifier.dashboard.requests.post", side_effect=post) as send:
        notifier.notify_telemetry({"total_requests": 7, "top_clients": [{"ip": "198.51.100.9"}]})
        assert delivered.wait(timeout=2)
        notifier.close()
        assert send.call_args.args[0] == "http://dashboard.test/api/telemetry"
        assert send.call_args.kwargs["json"]["project_id"] == "test-app"
        assert send.call_args.kwargs["json"]["stats"]["top_clients"][0]["ip"] == "198.51.100.9"


def test_digest_schedule_calculates_a_future_time():
    import datetime as dt

    now = dt.datetime(2026, 10, 9, 12, 0)  # Friday
    seconds = seconds_until_next_digest("sun", 9, now=now)
    assert seconds == 45 * 60 * 60
