"""
SIEM Forwarder
Forwards logs to SIEM systems.
"""
class SIEMForwarder:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def forward_log(self, log_entry: dict):
        # Send to SIEM
        print(f"Forwarding to {self.endpoint}: {log_entry}")
