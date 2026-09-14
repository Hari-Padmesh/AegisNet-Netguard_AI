"""
netguard/notifier/email_notifier.py
-----------------------------------
SMTP email notification dispatcher for critical attacks.
"""

import logging
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from netguard.alerts import Alert, Severity

logger = logging.getLogger("netguard.notifier.email")


class EmailNotifier:
    """
    Sends email alerts to administrators/moderators when significant attacks occur.

    Parameters
    ----------
    smtp_host : str
        SMTP server host (e.g. smtp.gmail.com).
    smtp_port : int
        SMTP server port (e.g. 587 for STARTTLS, 465 for SSL).
    username : str
        SMTP username/sender email address.
    password : str
        SMTP password or app-specific password.
    recipients : List[str]
        Recipient email addresses.
    use_tls : bool
        Whether to use STARTTLS (default True).
    min_severity : Severity
        Minimum severity to trigger email (default: Severity.HIGH).
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        recipients: List[str],
        use_tls: bool = True,
        min_severity: Severity = Severity.HIGH,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients
        self.use_tls = use_tls
        self.min_severity = min_severity

        self._severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

    def _severity_rank(self, s: Severity) -> int:
        try:
            return self._severity_order.index(s)
        except ValueError:
            return 0

    def send(self, alert: Alert, async_dispatch: bool = True) -> None:
        if self._severity_rank(alert.severity) < self._severity_rank(self.min_severity):
            return

        if async_dispatch:
            thread = threading.Thread(
                target=self._dispatch,
                args=(alert,),
                daemon=True,
                name=f"netguard-email-{alert.label}"
            )
            thread.start()
        else:
            self._dispatch(alert)

    def _dispatch(self, alert: Alert) -> None:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 [NetGuard Alert] {alert.severity.value}: {alert.label} detected"
            msg["From"] = self.username
            msg["To"] = ", ".join(self.recipients)

            html_content = f"""
            <html>
            <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px;">
                <div style="max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155;">
                    <h2 style="color: #ef4444; margin-top: 0;">🚨 Security Alert Triggered</h2>
                    <p>NetGuard AI detected suspicious network flow / request activity on your application:</p>
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr><td style="padding: 8px; color: #94a3b8;">Threat Class:</td><td style="padding: 8px; font-weight: bold; color: #f8fafc;">{alert.label}</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Severity:</td><td style="padding: 8px; font-weight: bold; color: #ef4444;">{alert.severity.value}</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Confidence:</td><td style="padding: 8px;">{alert.confidence:.1%}</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Timestamp:</td><td style="padding: 8px;">{alert.timestamp}</td></tr>
                        <tr><td style="padding: 8px; color: #94a3b8;">Summary:</td><td style="padding: 8px; font-family: monospace;">{alert.flow_summary}</td></tr>
                    </table>
                    <p style="font-size: 12px; color: #64748b; margin-bottom: 0;">Automated alert from NetGuard AI Threat Shield.</p>
                </div>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_content, "html"))

            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10)

            server.login(self.username, self.password)
            server.sendmail(self.username, self.recipients, msg.as_string())
            server.quit()
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
