"""
Core data models for the NetSec Platform.

Defines the fundamental data structures used throughout the platform:
- Packets (raw and decoded)
- Flows/Conversations
- Hosts/Assets
- Evidence artifacts
- Security findings
"""

from enum import Enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from uuid import uuid4


# ============================================================================
# Packet Models
# ============================================================================

@dataclass
class RawPacket:
    """Raw packet data with metadata."""
    packet_id: int  # Capture sequence number
    timestamp: datetime
    interface: str
    data: bytes  # Raw packet bytes
    captured_length: int
    original_length: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp.isoformat(),
            "interface": self.interface,
            "captured_length": self.captured_length,
            "original_length": self.original_length,
        }


@dataclass
class DecodedPacket:
    """Decoded packet with protocol layers."""
    packet_id: int
    timestamp: datetime
    layers: List[Dict[str, Any]]  # Protocol layers (Ethernet, IP, TCP, etc.)
    protocols: List[str]  # Protocol stack
    payload: Optional[bytes] = None  # Application payload if available
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Link to flow
    flow_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp.isoformat(),
            "protocols": self.protocols,
            "flow_id": self.flow_id,
            "metadata": self.metadata,
        }


# ============================================================================
# Network Address Models
# ============================================================================

@dataclass
class MACAddress:
    """MAC address representation."""
    address: str  # Format: "00:11:22:33:44:55"
    oui: Optional[str] = None  # Organizationally Unique Identifier
    
    @classmethod
    def from_string(cls, mac: str) -> "MACAddress":
        return cls(address=mac.upper().replace("-", ":"))
    
    def __str__(self) -> str:
        return self.address


@dataclass
class IPAddress:
    """IP address representation (IPv4 or IPv6)."""
    address: str
    version: int  # 4 or 6
    is_private: bool = False
    is_multicast: bool = False
    
    @classmethod
    def from_string(cls, ip: str) -> "IPAddress":
        version = 6 if ":" in ip else 4
        # Simple private range detection
        is_private = (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or
            ip.startswith("172.30.") or
            ip.startswith("172.31.")
        )
        is_multicast = ip.startswith("224.") or ip.startswith("ff")
        return cls(address=ip, version=version, is_private=is_private, is_multicast=is_multicast)


# ============================================================================
# Flow/Conversation Models
# ============================================================================

class TransportProtocol(str, Enum):
    """Transport layer protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPV6"
    OTHER = "OTHER"


class EncryptionState(str, Enum):
    """Encryption state of a connection."""
    PLAINTEXT = "plaintext"
    ENCRYPTED = "encrypted"
    DECRYPTED = "decrypted"
    PARTIALLY_DECODED = "partially_decoded"
    UNKNOWN = "unknown"


class SecurityQuality(str, Enum):
    """Security quality assessment."""
    GOOD = "good"
    WEAK = "weak"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


@dataclass
class NetworkFlow:
    """
    Network flow/conversation representation.
    
    A flow represents a bidirectional conversation between two endpoints.
    """
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport_proto: TransportProtocol
    app_proto: Optional[str] = None  # Application protocol (HTTP, DNS, TLS, etc.)
    
    # MAC addresses if available
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    
    # Timing
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Statistics
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # TCP-specific
    tcp_state: Optional[str] = None  # SYN_SENT, ESTABLISHED, FIN_WAIT, etc.
    retransmissions: int = 0
    rtt_estimate_ms: Optional[float] = None
    
    # Security classification
    encryption_state: EncryptionState = EncryptionState.UNKNOWN
    security_quality: SecurityQuality = SecurityQuality.UNKNOWN
    
    # Associated data
    packet_ids: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> float:
        """Calculate flow duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()
    
    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "transport_proto": self.transport_proto.value,
            "app_proto": self.app_proto,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "encryption_state": self.encryption_state.value,
            "security_quality": self.security_quality.value,
        }


# ============================================================================
# Asset/Host Models
# ============================================================================

@dataclass
class Asset:
    """
    Network asset/host representation.
    
    Represents a discovered device on the network.
    """
    asset_id: str
    mac_addresses: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    dns_names: List[str] = field(default_factory=list)
    
    # Discovered services
    services: List[Dict[str, Any]] = field(default_factory=list)  # [{port, proto, service_name}]
    open_ports: List[int] = field(default_factory=list)
    
    # Device fingerprinting
    device_type: Optional[str] = None  # server, workstation, iot, network_device, etc.
    os_fingerprint: Optional[str] = None
    vendor: Optional[str] = None
    
    # Timing
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Relationships
    connections: List[str] = field(default_factory=list)  # Flow IDs
    findings: List[str] = field(default_factory=list)  # Finding IDs
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "mac_addresses": self.mac_addresses,
            "ip_addresses": self.ip_addresses,
            "hostnames": self.hostnames,
            "services": self.services,
            "open_ports": self.open_ports,
            "device_type": self.device_type,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "connection_count": len(self.connections),
            "finding_count": len(self.findings),
        }


# ============================================================================
# Sensitive Data & Evidence Models
# ============================================================================

class ArtifactType(str, Enum):
    """Types of sensitive authentication/security artifacts."""
    PASSWORD = "password"
    SESSION_COOKIE = "session_cookie"
    AUTH_COOKIE = "auth_cookie"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    JWT = "jwt"
    API_KEY = "api_key"
    CSRF_TOKEN = "csrf_token"
    OAUTH_ARTIFACT = "oauth_artifact"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    DATABASE_CREDENTIAL = "database_credential"
    UNKNOWN_SECRET = "unknown_secret"
    PERSONAL_INFORMATION = "personal_information"
    EMAIL = "email"
    PHONE_NUMBER = "phone_number"
    ADDRESS = "address"


class DetectionConfidence(str, Enum):
    """Confidence level in a detection."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_DETERMINED = "not_determined"


@dataclass
class SensitiveArtifact:
    """
    Detected sensitive data artifact.
    
    Represents credentials, tokens, cookies, or other sensitive information
    observed in network traffic.
    """
    artifact_id: str  # EID - Evidence ID
    artifact_type: ArtifactType
    field_name: Optional[str] = None  # e.g., "username", "SESSIONID", "Authorization"
    
    # Location info
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    host: Optional[str] = None
    
    # Protocol info
    protocol: Optional[str] = None
    app_protocol: Optional[str] = None
    http_method: Optional[str] = None
    url_path: Optional[str] = None
    
    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # References
    flow_id: Optional[str] = None
    packet_id: Optional[int] = None
    capture_id: Optional[str] = None
    
    # Security context
    transport_encryption: EncryptionState = EncryptionState.UNKNOWN
    confidence: DetectionConfidence = DetectionConfidence.MEDIUM
    
    # Encrypted storage reference (actual value stored securely)
    encrypted_value_ref: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type.value,
            "field_name": self.field_name,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "app_protocol": self.app_protocol,
            "timestamp": self.timestamp.isoformat(),
            "flow_id": self.flow_id,
            "packet_id": self.packet_id,
            "transport_encryption": self.transport_encryption.value,
            "confidence": self.confidence.value,
        }


# ============================================================================
# Security Findings
# ============================================================================

class FindingSeverity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Status of a security finding."""
    NEW = "new"
    CONFIRMED = "confirmed"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class FindingConfidence(str, Enum):
    """Confidence in a security finding."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecurityFinding:
    """
    Security finding/vulnerability.
    
    Represents a detected security issue or weakness.
    """
    finding_id: str
    title: str
    severity: FindingSeverity
    confidence: FindingConfidence
    status: FindingStatus = FindingStatus.NEW
    
    description: str = ""
    explanation: str = ""
    remediation: str = ""
    
    # Affected entities
    affected_asset: Optional[str] = None  # Asset ID
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    
    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Evidence references
    evidence_ids: List[str] = field(default_factory=list)  # EIDs
    packet_references: List[int] = field(default_factory=list)  # Packet IDs
    flow_id: Optional[str] = None
    
    # Case association
    case_id: Optional[str] = None
    
    # Related findings
    related_findings: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "description": self.description,
            "affected_asset": self.affected_asset,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "timestamp": self.timestamp.isoformat(),
            "evidence_count": len(self.evidence_ids),
        }


# ============================================================================
# DNS Analysis Models
# ============================================================================

@dataclass
class DNSQuery:
    """DNS query record."""
    query_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str  # DNS server
    query_name: str
    query_type: str  # A, AAAA, MX, TXT, etc.
    
    # Response info (if available)
    response_code: Optional[str] = None  # NOERROR, NXDOMAIN, SERVFAIL, etc.
    answer_records: List[Dict[str, Any]] = field(default_factory=list)
    cname_chain: List[str] = field(default_factory=list)
    ttl: Optional[int] = None
    
    # Correlation
    flow_id: Optional[str] = None
    packet_id: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "response_code": self.response_code,
        }


# ============================================================================
# TLS Analysis Models
# ============================================================================

@dataclass
class TLSConnection:
    """TLS connection metadata."""
    tls_id: str
    flow_id: str
    
    # TLS version
    version: Optional[str] = None  # TLS 1.2, TLS 1.3, etc.
    
    # ClientHello info
    sni: Optional[str] = None  # Server Name Indication
    alpn: List[str] = field(default_factory=list)  # Application-Layer Protocol Negotiation
    
    # Cipher suite
    cipher_suite: Optional[str] = None
    
    # Certificate info (from ServerHello)
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_san: List[str] = field(default_factory=list)  # Subject Alternative Names
    cert_valid_from: Optional[datetime] = None
    cert_valid_until: Optional[datetime] = None
    cert_chain_length: Optional[int] = None
    
    # Security assessment
    security_quality: SecurityQuality = SecurityQuality.UNKNOWN
    weaknesses: List[str] = field(default_factory=list)  # e.g., "deprecated_tls", "weak_cipher"
    
    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tls_id": self.tls_id,
            "flow_id": self.flow_id,
            "version": self.version,
            "sni": self.sni,
            "cipher_suite": self.cipher_suite,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "security_quality": self.security_quality.value,
            "weaknesses": self.weaknesses,
        }


# ============================================================================
# HTTP Analysis Models
# ============================================================================

@dataclass
class HTTPTransaction:
    """HTTP request/response transaction."""
    transaction_id: str
    flow_id: str
    
    # Request
    method: str
    host: str
    uri: str
    query_params: Optional[Dict[str, str]] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: Optional[str] = None
    content_type: Optional[str] = None
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    
    # Response
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    
    # Auth info (detected, not logged)
    auth_method: Optional[str] = None  # basic, bearer, cookie, etc.
    has_credentials: bool = False
    has_session_info: bool = False
    
    # Security findings
    sensitive_in_url: bool = False
    sensitive_in_headers: bool = False
    insecure_auth: bool = False
    
    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # References
    request_packet_id: Optional[int] = None
    response_packet_id: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "flow_id": self.flow_id,
            "method": self.method,
            "host": self.host,
            "uri": self.uri,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "has_credentials": self.has_credentials,
            "has_session_info": self.has_session_info,
            "timestamp": self.timestamp.isoformat(),
        }
