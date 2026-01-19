"""
Email parsing utilities for extracting information from email messages.
"""
import re
from email.header import decode_header
from bs4 import BeautifulSoup


def extract_email_body(msg):
    """
    Extract the body text from an email message.
    
    Args:
        msg: email.message.Message object
        
    Returns:
        str: Extracted email body text
    """
    body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                break
            elif content_type == "text/html":
                html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                soup = BeautifulSoup(html, "html.parser")
                body = soup.get_text()
    else:
        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
    
    return body.strip()


def extract_urls(text):
    """
    Extract URLs from text using regex.
    
    Args:
        text (str): Text to extract URLs from
        
    Returns:
        list: List of URLs found in the text
    """
    return re.findall(r'https?://\S+', text)


def extract_ips(text):
    """
    Extract IP addresses from text using regex.
    
    Args:
        text (str): Text to extract IPs from
        
    Returns:
        list: List of IP addresses found in the text
    """
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)


def decode_email_subject(subject_header):
    """
    Decode email subject header.
    
    Args:
        subject_header: Raw subject header from email
        
    Returns:
        str: Decoded subject string
    """
    if not subject_header:
        return ""
    
    subject, encoding = decode_header(subject_header)[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or "utf-8", errors="ignore")
    
    return subject
