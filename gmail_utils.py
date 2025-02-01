import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
import email
import re

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_gmail_service():
    creds = None
    # The file token.json stores the user's access and refresh tokens
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


def extract_email_metadata(message):
    """
    Extract metadata from a Gmail message
    """
    msg_raw = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
    email_message = email.message_from_bytes(msg_raw)

    # Extract headers
    headers = {h['name']: h['value'] for h in message.get('payload', {}).get('headers', [])}

    # Extract body and look for URLs and IPs
    urls = []
    ips = []

    # Extract from body if it's a text/plain part
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode()
                urls.extend(
                    re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                               body))
                ips.extend(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', body))

    return {
        'headers': headers,
        'urls': urls,
        'ips': ips
    }


def list_emails(service, max_results=10):
    """
    List emails from Gmail
    """
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    return results.get('messages', [])


def get_email_details(service, msg_id):
    """
    Get full email details
    """
    message = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
    return message