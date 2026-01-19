"""Services package initialization."""
from .email_service import fetch_emails
from .virustotal_service import check_url_virustotal, check_ip_virustotal
from .alert_service import send_security_alert, format_alert_body

__all__ = [
    'fetch_emails',
    'check_url_virustotal',
    'check_ip_virustotal',
    'send_security_alert',
    'format_alert_body'
]
