"""
Email service for fetching and processing emails from various providers.
"""
import imaplib
import email
from src.config import IMAP_SERVERS
from src.utils.email_parser import extract_email_body, extract_urls, extract_ips, decode_email_subject


def fetch_emails(email_user, app_password, provider, folder="INBOX", num_emails=5):
    """
    Fetch emails from the specified email provider.
    
    Args:
        email_user (str): Email address
        app_password (str): App password for email account
        provider (str): Email provider (Gmail, Outlook, Yahoo)
        folder (str): Email folder to fetch from (default: INBOX)
        num_emails (int): Number of emails to fetch (default: 5)
        
    Returns:
        list or str: List of email dictionaries on success, error message on failure
    """
    try:
        imap_server = IMAP_SERVERS.get(provider)
        if not imap_server:
            return f"Unsupported email provider: {provider}"

        # Connect to IMAP server
        mail = imaplib.IMAP4_SSL(imap_server, 993)
        mail.login(email_user, app_password)
        mail.select(folder)

        # Search for all emails
        status, messages = mail.search(None, "ALL")
        mail_ids = messages[0].split()[-num_emails:]

        email_list = []
        for mail_id in reversed(mail_ids):
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Extract email metadata
                    subject = decode_email_subject(msg.get("Subject"))
                    sender = msg.get("From")
                    body = extract_email_body(msg)
                    urls = extract_urls(body)
                    ips = extract_ips(body)
                    
                    email_list.append({
                        "Subject": subject,
                        "From": sender,
                        "Body": body,
                        "URLs": urls,
                        "IPs": ips
                    })
        
        mail.logout()
        return email_list
        
    except imaplib.IMAP4.error as e:
        return f"IMAP Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"
