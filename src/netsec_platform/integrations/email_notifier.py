"""
Email Notifier
Sends alert emails.
"""
class EmailNotifier:
    def __init__(self, smtp_server: str):
        self.smtp_server = smtp_server

    def send_alert(self, subject: str, body: str, recipients: list):
        print(f"Sending email to {recipients}: {subject}")
