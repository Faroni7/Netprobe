"""
MFA TOTP Implementation
Time-based One-Time Password authentication.
"""
import pyotp
import base64
import time

class MFAManager:
    def __init__(self):
        self.secret_store = {}  # In production, use encrypted DB

    def generate_secret(self, user_id: str) -> str:
        secret = pyotp.random_base32()
        self.secret_store[user_id] = secret
        return secret

    def get_provisioning_uri(self, user_id: str, issuer: str = "NetProbe") -> str:
        secret = self.secret_store.get(user_id)
        if not secret:
            raise ValueError("User secret not found")
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user_id, issuer_name=issuer)

    def verify_token(self, user_id: str, token: str) -> bool:
        secret = self.secret_store.get(user_id)
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
