"""
Webhook Manager
Manages outgoing webhooks.
"""
class WebhookManager:
    def __init__(self):
        self.webhooks = []

    def register_webhook(self, url: str):
        self.webhooks.append(url)

    def trigger(self, event: dict):
        for url in self.webhooks:
            print(f"Triggering webhook: {url}")
