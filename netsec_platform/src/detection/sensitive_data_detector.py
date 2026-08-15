"""
Sensitive Data Detector.

Detects sensitive information in network traffic including:
- Credentials (usernames, passwords)
- Session identifiers
- Tokens (JWT, API keys, OAuth)
- Cookies
- Personal information
"""

import logging
import re
from typing import Optional, Dict, Any, List, Pattern
from datetime import datetime, timezone
from dataclasses import dataclass
from uuid import uuid4

from netsec_platform.models.core_models import (
    SensitiveArtifact,
    ArtifactType,
    DetectionConfidence,
    EncryptionState,
)


logger = logging.getLogger(__name__)


@dataclass
class DetectionPattern:
    """Pattern for detecting sensitive data."""
    name: str
    pattern: Pattern
    artifact_type: ArtifactType
    confidence: DetectionConfidence


class SensitiveDataDetector:
    """
    Sensitive data detection engine.
    
    Scans data for sensitive information using configurable patterns.
    """
    
    def __init__(self):
        self._patterns: List[DetectionPattern] = []
        self._load_default_patterns()
        logger.info("SensitiveDataDetector initialized")
    
    def _load_default_patterns(self):
        """Load default detection patterns."""
        # Email pattern
        self._patterns.append(DetectionPattern(
            name="Email Address",
            pattern=re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            artifact_type=ArtifactType.EMAIL,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # Credit card pattern (basic Luhn-compatible)
        self._patterns.append(DetectionPattern(
            name="Credit Card Number",
            pattern=re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            artifact_type=ArtifactType.PERSONAL_INFORMATION,
            confidence=DetectionConfidence.MEDIUM,
        ))
        
        # US Phone number pattern
        self._patterns.append(DetectionPattern(
            name="US Phone Number",
            pattern=re.compile(r'\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b'),
            artifact_type=ArtifactType.PHONE_NUMBER,
            confidence=DetectionConfidence.MEDIUM,
        ))
        
        # JWT pattern
        self._patterns.append(DetectionPattern(
            name="JWT Token",
            pattern=re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
            artifact_type=ArtifactType.JWT,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # API Key patterns (common formats)
        self._patterns.append(DetectionPattern(
            name="Generic API Key",
            pattern=re.compile(r'(?:api[_-]?key|apikey)[=:\s]+["\']?[a-zA-Z0-9_-]{20,}["\']?', re.IGNORECASE),
            artifact_type=ArtifactType.API_KEY,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # AWS Access Key pattern
        self._patterns.append(DetectionPattern(
            name="AWS Access Key",
            pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
            artifact_type=ArtifactType.CLOUD_CREDENTIAL,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # GitHub token pattern
        self._patterns.append(DetectionPattern(
            name="GitHub Token",
            pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            artifact_type=ArtifactType.API_KEY,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # Private key header
        self._patterns.append(DetectionPattern(
            name="Private Key Header",
            pattern=re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            artifact_type=ArtifactType.PRIVATE_KEY,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # Password field patterns
        self._patterns.append(DetectionPattern(
            name="Password Field",
            pattern=re.compile(r'(?:password|passwd|pwd)[=:\s]+[^\s&]+', re.IGNORECASE),
            artifact_type=ArtifactType.PASSWORD,
            confidence=DetectionConfidence.MEDIUM,
        ))
        
        # Bearer token pattern
        self._patterns.append(DetectionPattern(
            name="Bearer Token",
            pattern=re.compile(r'[Bb]earer\s+[a-zA-Z0-9_\.-]+'),
            artifact_type=ArtifactType.BEARER_TOKEN,
            confidence=DetectionConfidence.HIGH,
        ))
        
        # Session cookie pattern
        self._patterns.append(DetectionPattern(
            name="Session Cookie",
            pattern=re.compile(r'(?:sessionid|session_id|sess_id|sid)[=:]([a-zA-Z0-9_-]{16,})', re.IGNORECASE),
            artifact_type=ArtifactType.SESSION_COOKIE,
            confidence=DetectionConfidence.MEDIUM,
        ))
    
    def add_custom_pattern(
        self,
        name: str,
        regex: str,
        artifact_type: ArtifactType,
        confidence: DetectionConfidence = DetectionConfidence.MEDIUM,
    ):
        """Add a custom detection pattern."""
        try:
            pattern = re.compile(regex)
            self._patterns.append(DetectionPattern(
                name=name,
                pattern=pattern,
                artifact_type=artifact_type,
                confidence=confidence,
            ))
            logger.debug(f"Added custom pattern: {name}")
        except re.error as e:
            logger.error(f"Invalid regex pattern '{name}': {e}")
    
    def scan_text(
        self,
        text: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        flow_id: Optional[str] = None,
        packet_id: Optional[int] = None,
        protocol: Optional[str] = None,
        transport_encryption: EncryptionState = EncryptionState.UNKNOWN,
    ) -> List[SensitiveArtifact]:
        """Scan text content for sensitive data."""
        artifacts = []
        timestamp = timestamp or datetime.now(timezone.utc)
        
        for detection_pattern in self._patterns:
            matches = detection_pattern.pattern.finditer(text)
            
            for match in matches:
                matched_text = match.group(0)
                
                # Skip if match is too short or looks like false positive
                if len(matched_text) < 8:
                    continue
                
                artifact = SensitiveArtifact(
                    artifact_id=f"eid-{uuid4().hex[:8]}",
                    artifact_type=detection_pattern.artifact_type,
                    field_name=detection_pattern.name,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    timestamp=timestamp,
                    flow_id=flow_id,
                    packet_id=packet_id,
                    transport_encryption=transport_encryption,
                    confidence=detection_pattern.confidence,
                    metadata={
                        "matched_text_preview": matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                        "match_position": match.start(),
                    },
                )
                artifacts.append(artifact)
        
        return artifacts
    
    def scan_http_body(
        self,
        body: bytes,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        timestamp: datetime,
        flow_id: Optional[str],
        packet_id: Optional[int],
        is_encrypted: bool = False,
    ) -> List[SensitiveArtifact]:
        """Scan HTTP body for sensitive data."""
        encryption_state = (
            EncryptionState.ENCRYPTED if is_encrypted else EncryptionState.PLAINTEXT
        )
        
        try:
            # Try to decode as UTF-8
            text = body.decode('utf-8', errors='ignore')
            return self.scan_text(
                text=text,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                flow_id=flow_id,
                packet_id=packet_id,
                protocol="HTTP",
                transport_encryption=encryption_state,
            )
        except Exception as e:
            logger.debug(f"Failed to scan HTTP body: {e}")
            return []
    
    def scan_headers(
        self,
        headers: Dict[str, str],
        src_ip: Optional[str],
        dst_ip: Optional[str],
        timestamp: datetime,
        flow_id: Optional[str],
        packet_id: Optional[int],
        protocol: str = "HTTP",
        transport_encryption: EncryptionState = EncryptionState.UNKNOWN,
    ) -> List[SensitiveArtifact]:
        """Scan HTTP headers for sensitive data."""
        artifacts = []
        
        for header_name, header_value in headers.items():
            # Check header name for sensitive indicators
            header_lower = header_name.lower()
            if any(indicator in header_lower for indicator in ['auth', 'token', 'key', 'secret']):
                artifact = SensitiveArtifact(
                    artifact_id=f"eid-header-{uuid4().hex[:8]}",
                    artifact_type=ArtifactType.UNKNOWN_SECRET,
                    field_name=header_name,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    timestamp=timestamp,
                    flow_id=flow_id,
                    packet_id=packet_id,
                    transport_encryption=transport_encryption,
                    confidence=DetectionConfidence.MEDIUM,
                    metadata={"header_name": header_name},
                )
                artifacts.append(artifact)
            
            # Scan header value
            value_artifacts = self.scan_text(
                text=header_value,
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=timestamp,
                flow_id=flow_id,
                packet_id=packet_id,
                protocol=protocol,
                transport_encryption=transport_encryption,
            )
            artifacts.extend(value_artifacts)
        
        return artifacts
    
    def detect_jwt_metadata(self, jwt_token: str) -> Optional[Dict[str, Any]]:
        """Extract non-secret metadata from JWT token."""
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None
            
            import base64
            import json
            
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_padded)
            header = json.loads(header_json)
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_padded)
            payload = json.loads(payload_json)
            
            return {
                "algorithm": header.get("alg"),
                "key_id": header.get("kid"),
                "issuer": payload.get("iss"),
                "subject": payload.get("sub"),
                "audience": payload.get("aud"),
                "issued_at": payload.get("iat"),
                "expiration": payload.get("exp"),
                "not_before": payload.get("nbf"),
            }
            
        except Exception as e:
            logger.debug(f"Failed to parse JWT: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        pattern_counts = {}
        for pattern in self._patterns:
            type_name = pattern.artifact_type.value
            pattern_counts[type_name] = pattern_counts.get(type_name, 0) + 1
        
        return {
            "total_patterns": len(self._patterns),
            "patterns_by_type": pattern_counts,
        }
