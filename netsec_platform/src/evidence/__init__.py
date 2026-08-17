"""
Evidence Vault and Storage Module.

Provides secure storage for sensitive evidence with:
- Encryption at rest
- Access controls
- Audit logging
- Integrity verification
- Chain of custody tracking
"""

from .evidence_store import EvidenceStore, EvidenceVault
from .audit_logger import AuditLogger, AuditEvent

__all__ = [
    "EvidenceStore",
    "EvidenceVault",
    "AuditLogger",
    "AuditEvent",
]
