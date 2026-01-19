"""Configuration package initialization."""
from .settings import (
    VIRUSTOTAL_API_KEY,
    ALERT_EMAIL,
    ALERT_EMAIL_PASSWORD,
    IMAP_SERVERS,
    RESULTS_DIR,
    HISTORY_FILE,
    validate_config
)

__all__ = [
    'VIRUSTOTAL_API_KEY',
    'ALERT_EMAIL',
    'ALERT_EMAIL_PASSWORD',
    'IMAP_SERVERS',
    'RESULTS_DIR',
    'HISTORY_FILE',
    'validate_config'
]
