"""
Multi-Factor Authentication using TOTP (RFC 6238)

Implements time-based one-time passwords for MFA.
"""

import pyotp
import qrcode
import base64
from typing import Optional, Tuple
from datetime import datetime, timedelta
import secrets


class MFATOTPManager:
    """Manage TOTP-based multi-factor authentication"""
    
    def __init__(self, issuer: str = "NetSec Platform"):
        self.issuer = issuer
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, secret: str, username: str) -> str:
        """Generate provisioning URI for QR code"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=self.issuer)
    
    def generate_qr_code(self, secret: str, username: str) -> str:
        """
        Generate QR code as base64 PNG
        
        Returns:
            Base64-encoded PNG image
        """
        uri = self.get_provisioning_uri(secret, username)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        from io import BytesIO
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    def verify_totp(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Verify TOTP code
        
        Args:
            secret: User's TOTP secret
            code: Code provided by user
            window: Acceptable drift in time steps (default 1)
        
        Returns:
            True if valid, False otherwise
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=window)
    
    def generate_backup_codes(self, count: int = 10) -> list[str]:
        """Generate backup codes for account recovery"""
        codes = []
        for _ in range(count):
            code = '-'.join(secrets.token_hex(2).upper()[i:i+4] for i in range(0, 8, 4))
            codes.append(code)
        return codes
    
    def verify_backup_code(self, stored_codes: list[str], code: str) -> Tuple[bool, list[str]]:
        """
        Verify and consume a backup code
        
        Returns:
            Tuple of (is_valid, remaining_codes)
        """
        code_normalized = code.replace('-', '').upper()
        
        for i, stored in enumerate(stored_codes):
            if stored.replace('-', '') == code_normalized:
                # Remove used code
                remaining = stored_codes[:i] + stored_codes[i+1:]
                return True, remaining
        
        return False, stored_codes


# Backup code storage model (to be persisted in database)
class MFABackupCodes:
    """Store and manage backup codes"""
    
    def __init__(self, user_id: str, codes: list[str], created_at: datetime):
        self.user_id = user_id
        self.codes = codes
        self.created_at = created_at
        self.used_codes: list[str] = []
    
    def use_code(self, code: str) -> bool:
        """Mark a backup code as used"""
        if code in self.codes and code not in self.used_codes:
            self.used_codes.append(code)
            return True
        return False
    
    def remaining_codes(self) -> list[str]:
        """Get unused backup codes"""
        return [c for c in self.codes if c not in self.used_codes]


# Session data structure
class MFASession:
    """Track MFA verification state during login"""
    
    def __init__(self, user_id: str, requires_mfa: bool):
        self.user_id = user_id
        self.requires_mfa = requires_mfa
        self.mfa_verified = False
        self.created_at = datetime.utcnow()
        self.expires_at = self.created_at + timedelta(minutes=10)
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    def mark_verified(self):
        self.mfa_verified = True
