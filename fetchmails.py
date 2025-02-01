import streamlit as st
import imaplib
import email
from email.header import decode_header
from bs4 import BeautifulSoup
import re
import requests
import time
import pandas as pd
import os
import concurrent.futures

# Email Server Configuration
IMAP_SERVERS = {
    "Gmail": "imap.gmail.com",
    "Outlook": "imap-mail.outlook.com",
    "Yahoo": "imap.mail.yahoo.com"
}

# VirusTotal API Key
VIRUSTOTAL_API_KEY = ""
HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# Directory for storing scanned results
RESULTS_DIR = "scan_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def fetch_emails(email_user, app_password, provider, folder="INBOX", num_emails=5):
    try:
        imap_server = IMAP_SERVERS.get(provider)
        if not imap_server:
            return f"Unsupported email provider: {provider}"

        mail = imaplib.IMAP4_SSL(imap_server, 993)
        mail.login(email_user, app_password)
        mail.select(folder)

        status, messages = mail.search(None, "ALL")
        mail_ids = messages[0].split()[-num_emails:]

        email_list = []
        for mail_id in reversed(mail_ids):
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8")
                    sender = msg.get("From")
                    body = extract_email_body(msg)
                    urls = extract_urls(body)
                    
                    email_list.append({"Subject": subject, "From": sender, "Body": body, "URLs": urls})
        mail.logout()
        return email_list
    except Exception as e:
        return str(e)

def extract_email_body(msg):
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
    return re.findall(r'https?://\S+', text)

def check_url_virustotal(url):
    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=HEADERS, data={"url": url})
        if response.status_code != 200:
            return {}
        analysis_id = response.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {}
        
        for _ in range(5):
            time.sleep(2)
            report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=HEADERS)
            if report_response.status_code == 200:
                break
        
        report = report_response.json()
        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    except Exception as e:
        return {}

def main():
    st.title("📧 Email Scanner & Deep Analyzer")
    email_user = st.text_input("📩 Enter Your Email")
    app_password = st.text_input("🔑 Enter App Password", type="password")
    provider = st.selectbox("🌐 Select Email Provider", ["Gmail", "Outlook", "Yahoo"])
    num_emails = st.slider("📌 Number of Emails to Fetch", 1, 10, 5)

    if st.button("Fetch & Deep Scan Emails"):
        if email_user and app_password and provider:
            with st.spinner("Fetching emails..."):
                emails = fetch_emails(email_user, app_password, provider, num_emails=num_emails)
                if isinstance(emails, list):
                    email_data_list = []
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        futures = {executor.submit(check_url_virustotal, url): url for email_data in emails for url in email_data['URLs']}
                        url_scan_results = {futures[future]: future.result() for future in concurrent.futures.as_completed(futures)}
                    
                    for email_data in emails:
                        malicious_count = sum(1 for url in email_data['URLs'] if url_scan_results.get(url, {}).get('malicious', 0) > 0)
                        suspicious_count = sum(1 for url in email_data['URLs'] if url_scan_results.get(url, {}).get('suspicious', 0) > 0)
                        email_data_list.append({
                            "Subject": email_data["Subject"],
                            "From": email_data["From"],
                            "URLs Found": len(email_data["URLs"]),
                            "Malicious URLs": malicious_count,
                            "Suspicious URLs": suspicious_count
                        })
                    df = pd.DataFrame(email_data_list)
                    st.dataframe(df)
                else:
                    st.error(f"⚠️ {emails}")
        else:
            st.warning("⚠️ Please enter all required details.")

if _name_ == "_main_":
    main()