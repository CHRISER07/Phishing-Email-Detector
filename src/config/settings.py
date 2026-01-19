"""
Configuration management for the Phishing Email Detector application.
Loads environment variables and provides centralized settings.
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# VirusTotal Configuration
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

# Email Alert Configuration
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')
ALERT_EMAIL_PASSWORD = os.getenv('ALERT_EMAIL_PASSWORD', '')

# IMAP Server Configuration
IMAP_SERVERS = {
    "Gmail": "imap.gmail.com",
    "Outlook": "imap-mail.outlook.com",
    "Yahoo": "imap.mail.yahoo.com"
}

# Application Settings
RESULTS_DIR = "scan_results"
HISTORY_FILE = "history.json"

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

def validate_config():
    """Validate that required configuration is present."""
    missing = []
    
    if not VIRUSTOTAL_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    
    if missing:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Please copy .env.example to .env and fill in your values."
        )

# Validate configuration on import (optional - can be called explicitly)
# validate_config()
