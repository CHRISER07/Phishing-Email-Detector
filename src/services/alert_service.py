"""
Alert service for sending security notifications via email.
"""
import yagmail
from src.config import ALERT_EMAIL, ALERT_EMAIL_PASSWORD


def send_security_alert(recipient, subject, body):
    """
    Send security alert email using configured credentials.
    
    Args:
        recipient (str): Recipient email address
        subject (str): Email subject
        body (str): Email body content
        
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        # Check if alert email is configured
        if not ALERT_EMAIL or not ALERT_EMAIL_PASSWORD:
            print("Alert email not configured. Please set ALERT_EMAIL and ALERT_EMAIL_PASSWORD in .env")
            return False
        
        # Initialize yagmail SMTP
        yag = yagmail.SMTP(
            user=ALERT_EMAIL,
            password=ALERT_EMAIL_PASSWORD
        )

        # Send email
        yag.send(
            to=recipient,
            subject=subject,
            contents=body
        )
        
        return True
        
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def format_alert_body(email_data, malicious_urls, malicious_ips):
    """
    Format the alert email body with threat details.
    
    Args:
        email_data (dict): Email metadata
        malicious_urls (list): List of malicious URLs
        malicious_ips (list): List of malicious IPs
        
    Returns:
        str: Formatted email body
    """
    body = f"""
⚠️ SECURITY ALERT: Malicious Email Detected ⚠️

Subject: {email_data.get('Subject', 'N/A')}
From: {email_data.get('From', 'N/A')}

Detected Threats:
"""
    
    if malicious_urls:
        body += f"\n🔗 Malicious URLs ({len(malicious_urls)}):\n"
        for url in malicious_urls:
            body += f"  - {url}\n"
    
    if malicious_ips:
        body += f"\n🌐 Malicious IPs ({len(malicious_ips)}):\n"
        for ip in malicious_ips:
            body += f"  - {ip}\n"
    
    body += """
⚠️ Action Required:
- Do NOT click on any links in this email
- Do NOT download any attachments
- Mark this email as spam/phishing
- Delete the email immediately

This is an automated security alert from your Email Security Analyzer.
"""
    
    return body
