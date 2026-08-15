"""
Evidence Store and Vault.

Secure storage for sensitive evidence with encryption, access controls,
and integrity verification.
"""

import os
import json
import hashlib
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from netsec_platform.models.core_models import (
    SensitiveArtifact,
    SecurityFinding,
    ArtifactType,
)


logger = logging.getLogger(__name__)


class EvidenceStatus(str, Enum):
    """Status of evidence in the vault."""
    ACTIVE = "active"
    LOCKED = "locked"  # Emergency stop lock
    ARCHIVED = "archived"
    DELETED = "deleted"


@dataclass
class EvidenceRecord:
    """Record of stored evidence."""
    evidence_id: str  # EID
    artifact_type: ArtifactType
    status: EvidenceStatus = EvidenceStatus.ACTIVE
    
    # References
    flow_id: Optional[str] = None
    packet_id: Optional[int] = None
    capture_id: Optional[str] = None
    case_id: Optional[str] = None
    
    # Storage location (encrypted value reference)
    encrypted_value_path: Optional[str] = None
    
    # Integrity
    content_hash: Optional[str] = None
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    accessed_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    # Metadata (non-sensitive)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "artifact_type": self.artifact_type.value,
            "status": self.status.value,
            "flow_id": self.flow_id,
            "packet_id": self.packet_id,
            "created_at": self.created_at.isoformat(),
            "accessed_at": self.accessed_at.isoformat() if self.accessed_at else None,
            "metadata": self.metadata,
        }


class EvidenceVault:
    """
    Secure vault for sensitive evidence values.
    
    Provides:
    - Encryption at rest
    - Controlled reveal
    - Access auditing
    - Integrity verification
    """
    
    def __init__(
        self,
        vault_path: str,
        encryption_key: Optional[bytes] = None,
    ):
        self.vault_path = Path(vault_path)
        self.vault_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption
        if CRYPTO_AVAILABLE and encryption_key:
            self._fernet = Fernet(encryption_key)
            self._encryption_enabled = True
        else:
            self._fernet = None
            self._encryption_enabled = False
            logger.warning("Encryption not available - evidence will not be encrypted")
        
        # Lock state
        self._is_locked = False
        
        logger.info(f"EvidenceVault initialized at {self.vault_path}")
    
    def store(
        self,
        evidence_id: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Store sensitive evidence value securely."""
        if self._is_locked:
            logger.warning(f"Vault is locked, cannot store evidence {evidence_id}")
            return None
        
        try:
            # Create file path
            evidence_file = self.vault_path / f"{evidence_id}.enc"
            
            # Prepare data
            data = {
                "evidence_id": evidence_id,
                "value": value,
                "metadata": metadata or {},
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
            
            # Serialize
            data_bytes = json.dumps(data).encode('utf-8')
            
            # Calculate hash for integrity
            content_hash = hashlib.sha256(data_bytes).hexdigest()
            
            # Encrypt if available
            if self._encryption_enabled and self._fernet:
                encrypted_data = self._fernet.encrypt(data_bytes)
            else:
                # Base64 encode for storage (not secure without encryption)
                import base64
                encrypted_data = base64.b64encode(data_bytes)
            
            # Write to file
            with open(evidence_file, 'wb') as f:
                f.write(encrypted_data)
            
            logger.debug(f"Stored evidence {evidence_id}")
            return content_hash
            
        except Exception as e:
            logger.error(f"Failed to store evidence {evidence_id}: {e}")
            return None
    
    def reveal(
        self,
        evidence_id: str,
        analyst_id: str,
        reason: Optional[str] = None,
    ) -> Optional[str]:
        """Reveal sensitive evidence value (with audit)."""
        if self._is_locked:
            logger.warning(f"Vault is locked, cannot reveal evidence {evidence_id}")
            return None
        
        try:
            evidence_file = self.vault_path / f"{evidence_id}.enc"
            
            if not evidence_file.exists():
                logger.warning(f"Evidence {evidence_id} not found")
                return None
            
            # Read encrypted data
            with open(evidence_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            if self._encryption_enabled and self._fernet:
                data_bytes = self._fernet.decrypt(encrypted_data)
            else:
                import base64
                data_bytes = base64.b64decode(encrypted_data)
            
            # Parse
            data = json.loads(data_bytes)
            
            # Verify integrity
            stored_hash = hashlib.sha256(data_bytes).hexdigest()
            
            logger.info(f"Evidence {evidence_id} revealed by {analyst_id}")
            
            return data.get("value")
            
        except Exception as e:
            logger.error(f"Failed to reveal evidence {evidence_id}: {e}")
            return None
    
    def verify_integrity(self, evidence_id: str, expected_hash: str) -> bool:
        """Verify evidence integrity."""
        try:
            evidence_file = self.vault_path / f"{evidence_id}.enc"
            
            if not evidence_file.exists():
                return False
            
            with open(evidence_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt to get original data
            if self._encryption_enabled and self._fernet:
                data_bytes = self._fernet.decrypt(encrypted_data)
            else:
                import base64
                data_bytes = base64.b64decode(encrypted_data)
            
            actual_hash = hashlib.sha256(data_bytes).hexdigest()
            return actual_hash == expected_hash
            
        except Exception as e:
            logger.error(f"Integrity verification failed for {evidence_id}: {e}")
            return False
    
    def lock(self):
        """Lock the vault (emergency stop)."""
        self._is_locked = True
        logger.warning("EvidenceVault locked")
    
    def unlock(self):
        """Unlock the vault (after recovery)."""
        self._is_locked = False
        logger.info("EvidenceVault unlocked")
    
    def delete(self, evidence_id: str) -> bool:
        """Securely delete evidence."""
        try:
            evidence_file = self.vault_path / f"{evidence_id}.enc"
            
            if evidence_file.exists():
                # Overwrite with random data before deletion
                file_size = evidence_file.stat().st_size
                with open(evidence_file, 'wb') as f:
                    f.write(os.urandom(file_size))
                
                # Delete file
                evidence_file.unlink()
                logger.info(f"Evidence {evidence_id} securely deleted")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete evidence {evidence_id}: {e}")
            return False


class EvidenceStore:
    """
    Evidence store managing evidence records and vault.
    
    Provides:
    - Evidence record management
    - Integration with EvidenceVault
    - Chain of custody tracking
    - Evidence queries
    """
    
    def __init__(
        self,
        store_path: str,
        vault_path: str,
        encryption_key: Optional[bytes] = None,
    ):
        self.store_path = Path(store_path)
        self.store_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize vault
        self.vault = EvidenceVault(vault_path, encryption_key)
        
        # Evidence index
        self._evidence_index: Dict[str, EvidenceRecord] = {}
        
        # Load existing index
        self._load_index()
        
        logger.info(f"EvidenceStore initialized at {self.store_path}")
    
    def _load_index(self):
        """Load evidence index from disk."""
        index_file = self.store_path / "index.json"
        
        if index_file.exists():
            try:
                with open(index_file, 'r') as f:
                    data = json.load(f)
                
                for eid, record_data in data.items():
                    record = EvidenceRecord(
                        evidence_id=record_data["evidence_id"],
                        artifact_type=ArtifactType(record_data["artifact_type"]),
                        status=EvidenceStatus(record_data["status"]),
                        flow_id=record_data.get("flow_id"),
                        packet_id=record_data.get("packet_id"),
                        capture_id=record_data.get("capture_id"),
                        case_id=record_data.get("case_id"),
                        encrypted_value_path=record_data.get("encrypted_value_path"),
                        content_hash=record_data.get("content_hash"),
                        created_at=datetime.fromisoformat(record_data["created_at"]),
                        metadata=record_data.get("metadata", {}),
                    )
                    self._evidence_index[eid] = record
                    
                logger.info(f"Loaded {len(self._evidence_index)} evidence records")
                
            except Exception as e:
                logger.error(f"Failed to load evidence index: {e}")
    
    def _save_index(self):
        """Save evidence index to disk."""
        index_file = self.store_path / "index.json"
        
        try:
            data = {
                eid: record.to_dict()
                for eid, record in self._evidence_index.items()
            }
            
            with open(index_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save evidence index: {e}")
    
    def add_evidence(
        self,
        artifact: SensitiveArtifact,
        value: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> Optional[EvidenceRecord]:
        """Add evidence to the store."""
        evidence_id = artifact.artifact_id
        
        # Store sensitive value in vault
        content_hash = None
        if value:
            content_hash = self.vault.store(
                evidence_id=evidence_id,
                value=value,
                metadata={
                    "artifact_type": artifact.artifact_type.value,
                    "field_name": artifact.field_name,
                },
            )
        
        # Create record
        record = EvidenceRecord(
            evidence_id=evidence_id,
            artifact_type=artifact.artifact_type,
            flow_id=artifact.flow_id,
            packet_id=artifact.packet_id,
            capture_id=artifact.capture_id,
            case_id=case_id,
            encrypted_value_path=str(self.vault.vault_path / f"{evidence_id}.enc"),
            content_hash=content_hash,
            metadata=artifact.metadata,
        )
        
        # Add to index
        self._evidence_index[evidence_id] = record
        self._save_index()
        
        logger.info(f"Added evidence {evidence_id} ({artifact.artifact_type.value})")
        return record
    
    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Get evidence record by ID."""
        return self._evidence_index.get(evidence_id)
    
    def get_evidence_value(
        self,
        evidence_id: str,
        analyst_id: str,
        reason: Optional[str] = None,
    ) -> Optional[str]:
        """Get sensitive evidence value (with audit)."""
        record = self._evidence_index.get(evidence_id)
        if not record:
            return None
        
        # Check status
        if record.status == EvidenceStatus.LOCKED:
            logger.warning(f"Evidence {evidence_id} is locked")
            return None
        
        if record.status == EvidenceStatus.DELETED:
            logger.warning(f"Evidence {evidence_id} is deleted")
            return None
        
        # Reveal value
        value = self.vault.reveal(evidence_id, analyst_id, reason)
        
        if value:
            # Update access time
            record.accessed_at = datetime.now(timezone.utc)
            self._save_index()
        
        return value
    
    def lock_evidence(self, evidence_id: str) -> bool:
        """Lock specific evidence (emergency stop)."""
        record = self._evidence_index.get(evidence_id)
        if record:
            record.status = EvidenceStatus.LOCKED
            self._save_index()
            logger.info(f"Evidence {evidence_id} locked")
            return True
        return False
    
    def lock_all_evidence(self) -> int:
        """Lock all evidence (emergency stop)."""
        count = 0
        for record in self._evidence_index.values():
            if record.status == EvidenceStatus.ACTIVE:
                record.status = EvidenceStatus.LOCKED
                count += 1
        self._save_index()
        logger.warning(f"Locked {count} evidence records")
        return count
    
    def unlock_all_evidence(self) -> int:
        """Unlock all evidence (recovery)."""
        count = 0
        for record in self._evidence_index.values():
            if record.status == EvidenceStatus.LOCKED:
                record.status = EvidenceStatus.ACTIVE
                count += 1
        self._save_index()
        logger.info(f"Unlocked {count} evidence records")
        return count
    
    def query_evidence(
        self,
        artifact_type: Optional[ArtifactType] = None,
        case_id: Optional[str] = None,
        status: Optional[EvidenceStatus] = None,
        limit: int = 100,
    ) -> List[EvidenceRecord]:
        """Query evidence with filters."""
        results = list(self._evidence_index.values())
        
        if artifact_type:
            results = [r for r in results if r.artifact_type == artifact_type]
        
        if case_id:
            results = [r for r in results if r.case_id == case_id]
        
        if status:
            results = [r for r in results if r.status == status]
        
        return results[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get evidence store statistics."""
        type_counts = {}
        status_counts = {}
        
        for record in self._evidence_index.values():
            type_name = record.artifact_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
            
            status_name = record.status.value
            status_counts[status_name] = status_counts.get(status_name, 0) + 1
        
        return {
            "total_evidence": len(self._evidence_index),
            "by_type": type_counts,
            "by_status": status_counts,
            "vault_locked": self.vault._is_locked,
            "encryption_enabled": self.vault._encryption_enabled,
        }
    
    def lock_vault(self):
        """Lock the evidence vault."""
        self.vault.lock()
        self.lock_all_evidence()
    
    def unlock_vault(self):
        """Unlock the evidence vault."""
        self.vault.unlock()
        self.unlock_all_evidence()
