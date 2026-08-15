"""Models module for NetSec Platform."""

from netsec_platform.models.core_models import (
    # Packet models
    RawPacket,
    DecodedPacket,
    # Network addresses
    MACAddress,
    IPAddress,
    # Flow models
    TransportProtocol,
    EncryptionState,
    SecurityQuality,
    NetworkFlow,
    # Asset models
    Asset,
    # Sensitive data & evidence
    ArtifactType,
    DetectionConfidence,
    SensitiveArtifact,
    # Security findings
    FindingSeverity,
    FindingStatus,
    FindingConfidence,
    SecurityFinding,
    # DNS analysis
    DNSQuery,
    # TLS analysis
    TLSConnection,
    # HTTP analysis
    HTTPTransaction,
)

__all__ = [
    # Packet models
    "RawPacket",
    "DecodedPacket",
    # Network addresses
    "MACAddress",
    "IPAddress",
    # Flow models
    "TransportProtocol",
    "EncryptionState",
    "SecurityQuality",
    "NetworkFlow",
    # Asset models
    "Asset",
    # Sensitive data & evidence
    "ArtifactType",
    "DetectionConfidence",
    "SensitiveArtifact",
    # Security findings
    "FindingSeverity",
    "FindingStatus",
    "FindingConfidence",
    "SecurityFinding",
    # DNS analysis
    "DNSQuery",
    # TLS analysis
    "TLSConnection",
    # HTTP analysis
    "HTTPTransaction",
]
