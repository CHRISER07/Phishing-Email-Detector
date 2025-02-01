import yagmail
import os
from dotenv import load_dotenv

load_dotenv()


def send_security_alert(recipient, subject, body):
    """
    Send security alert email using app password
    """
    try:
        # Initialize yagmail SMTP
        yag = yagmail.SMTP(
            user='jerjacmat@gmail.com',
            password='cehq ddgp mwtu qybe'  # App password
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