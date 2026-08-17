"""
Canonical Configuration Schema for NetSec Platform

This module defines the authoritative configuration schema used by:
- Backend validation (Pydantic)
- Frontend TypeScript types
- API documentation
- Configuration UI generation

Every setting defined here corresponds to actual backend functionality.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import timedelta


# ============================================================================
# ENUMS - Actual values supported by the implementation
# ============================================================================

class CaptureProfile(str, Enum):
    """Actual capture profiles implemented in packet_capture.py"""
    METADATA_ONLY = "metadata_only"
    STANDARD = "standard"
    FULL_EVIDENCE = "full_evidence"


class LogLevel(str, Enum):
    """Logging levels supported by structlog"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EnvironmentType(str, Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class HashAlgorithm(str, Enum):
    """Supported hashing algorithms for evidence"""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


# ============================================================================
# CONFIGURATION MODELS - Organized by category
# ============================================================================

class AppConfig(BaseModel):
    """General application settings"""
    environment: EnvironmentType = Field(
        default=EnvironmentType.DEVELOPMENT,
        description="Deployment environment",
        env="NETSEC_APP_ENV"
    )
    host: str = Field(
        default="127.0.0.1",
        description="API server bind address",
        env="NETSEC_APP_HOST"
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="API server port",
        env="NETSEC_APP_PORT"
    )
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Application logging level",
        env="NETSEC_LOG_LEVEL"
    )
    debug_mode: bool = Field(
        default=False,
        description="Enable debug mode (note: sensitive data always redacted)",
        env="NETSEC_DEBUG"
    )
    timezone: str = Field(
        default="UTC",
        description="Application timezone",
        env="NETSEC_TIMEZONE"
    )

    class Config:
        use_enum_values = True


class NetworkConfig(BaseModel):
    """Network and API exposure settings"""
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="CORS allowed origins",
        env="NETSEC_ALLOWED_ORIGINS"
    )
    trusted_proxies: List[str] = Field(
        default=[],
        description="Trusted reverse proxy IPs",
        env="NETSEC_TRUSTED_PROXIES"
    )
    request_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=300,
        description="HTTP request timeout",
        env="NETSEC_REQUEST_TIMEOUT"
    )
    max_request_size_mb: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum request size",
        env="NETSEC_MAX_REQUEST_SIZE"
    )
    rate_limit_per_minute: int = Field(
        default=100,
        ge=1,
        description="API rate limit per minute",
        env="NETSEC_RATE_LIMIT"
    )


class CaptureConfig(BaseModel):
    """Packet capture engine settings"""
    enabled: bool = Field(
        default=True,
        description="Enable packet capture",
        env="NETSEC_CAPTURE_ENABLED"
    )
    interface: Optional[str] = Field(
        default=None,
        description="Network interface to capture (null = auto-discover)",
        env="NETSEC_CAPTURE_INTERFACE"
    )
    profile: CaptureProfile = Field(
        default=CaptureProfile.STANDARD,
        description="Capture profile controlling data retention",
        env="NETSEC_CAPTURE_PROFILE"
    )
    filter: Optional[str] = Field(
        default=None,
        description="BPF capture filter",
        env="NETSEC_CAPTURE_FILTER"
    )
    snaplen_bytes: int = Field(
        default=65535,
        ge=64,
        le=65535,
        description="Packet snapshot length (note: currently hardcoded)",
        env="NETSEC_CAPTURE_SNAPLEN"
    )
    promiscuous_mode: bool = Field(
        default=True,
        description="Enable promiscuous mode",
        env="NETSEC_CAPTURE_PROMISC"
    )
    buffer_size_mb: int = Field(
        default=256,
        ge=64,
        le=4096,
        description="Capture buffer size",
        env="NETSEC_CAPTURE_BUFFER"
    )
    max_storage_gb: float = Field(
        default=100.0,
        ge=1.0,
        le=1000.0,
        description="Maximum storage for captures",
        env="NETSEC_CAPTURE_MAX_STORAGE"
    )
    worker_count: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Capture worker threads",
        env="NETSEC_CAPTURE_WORKERS"
    )
    queue_size: int = Field(
        default=10000,
        ge=1000,
        le=100000,
        description="Packet processing queue size",
        env="NETSEC_CAPTURE_QUEUE"
    )

    class Config:
        use_enum_values = True


class EvidenceConfig(BaseModel):
    """Evidence storage and integrity settings"""
    storage_path: str = Field(
        default="/var/netsec_platform/data/evidence",
        description="Evidence storage directory",
        env="NETSEC_EVIDENCE_PATH"
    )
    encryption_enabled: bool = Field(
        default=True,
        description="Encrypt evidence at rest (REQUIRED for production)",
        env="NETSEC_EVIDENCE_ENCRYPT"
    )
    encryption_key: Optional[str] = Field(
        default=None,
        description="AES-256-GCM encryption key (SET VIA ENV ONLY)",
        env="NETSEC_EVIDENCE_KEY",
        sensitive=True
    )
    hash_algorithm: HashAlgorithm = Field(
        default=HashAlgorithm.SHA256,
        description="Hashing algorithm for integrity",
        env="NETSEC_EVIDENCE_HASH"
    )
    retention_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Evidence retention period",
        env="NETSEC_EVIDENCE_RETENTION"
    )
    immutable_storage: bool = Field(
        default=False,
        description="Enable append-only storage",
        env="NETSEC_EVIDENCE_IMMUTABLE"
    )
    compression_enabled: bool = Field(
        default=False,
        description="Enable compression (note: not yet implemented)",
        env="NETSEC_EVIDENCE_COMPRESS"
    )
    backup_enabled: bool = Field(
        default=True,
        description="Enable automated backups",
        env="NETSEC_EVIDENCE_BACKUP"
    )

    class Config:
        use_enum_values = True


class AuthConfig(BaseModel):
    """Authentication and session settings"""
    session_timeout_minutes: int = Field(
        default=60,
        ge=5,
        le=1440,
        description="Session expiration time",
        env="NETSEC_AUTH_SESSION_TIMEOUT"
    )
    idle_timeout_minutes: int = Field(
        default=15,
        ge=1,
        le=120,
        description="Idle session timeout",
        env="NETSEC_AUTH_IDLE_TIMEOUT"
    )
    max_login_attempts: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Max failed login attempts before lockout",
        env="NETSEC_AUTH_MAX_ATTEMPTS"
    )
    lockout_duration_minutes: int = Field(
        default=30,
        ge=5,
        le=1440,
        description="Account lockout duration",
        env="NETSEC_AUTH_LOCKOUT_DURATION"
    )
    require_mfa: bool = Field(
        default=False,
        description="Require multi-factor authentication",
        env="NETSEC_AUTH_MFA_REQUIRED"
    )
    jwt_secret: Optional[str] = Field(
        default=None,
        description="JWT signing secret (SET VIA ENV ONLY)",
        env="NETSEC_AUTH_JWT_SECRET",
        sensitive=True
    )


class AuditConfig(BaseModel):
    """Audit logging settings"""
    enabled: bool = Field(
        default=True,
        description="Enable audit logging (cannot be disabled in production)",
        env="NETSEC_AUDIT_ENABLED"
    )
    storage_path: str = Field(
        default="/var/netsec_platform/logs/audit",
        description="Audit log storage directory",
        env="NETSEC_AUDIT_PATH"
    )
    retention_days: int = Field(
        default=90,
        ge=30,
        le=730,
        description="Audit log retention period",
        env="NETSEC_AUDIT_RETENTION"
    )
    include_request_body: bool = Field(
        default=False,
        description="Include request bodies in audit (security risk)",
        env="NETSEC_AUDIT_INCLUDE_BODY"
    )
    remote_destination: Optional[str] = Field(
        default=None,
        description="Remote syslog destination",
        env="NETSEC_AUDIT_REMOTE"
    )


class TestingConfig(BaseModel):
    """Authorized pentesting configuration"""
    enabled: bool = Field(
        default=False,
        description="Enable controlled testing module",
        env="NETSEC_TESTING_ENABLED"
    )
    require_authorization: bool = Field(
        default=True,
        description="Require written authorization reference (CANNOT disable)",
        env="NETSEC_TESTING_REQUIRE_AUTHZ",
        locked=True
    )
    require_scope: bool = Field(
        default=True,
        description="Require target scope validation (CANNOT disable)",
        env="NETSEC_TESTING_REQUIRE_SCOPE",
        locked=True
    )
    max_rate_limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum test requests per minute",
        env="NETSEC_TESTING_RATE_LIMIT"
    )
    max_duration_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Maximum test duration",
        env="NETSEC_TESTING_MAX_DURATION"
    )
    emergency_stop_enabled: bool = Field(
        default=True,
        description="Enable emergency stop for tests (CANNOT disable)",
        env="NETSEC_TESTING_EMERGENCY_STOP",
        locked=True
    )


class ESSConfig(BaseModel):
    """Emergency Security Stop configuration"""
    enabled: bool = Field(
        default=True,
        description="Enable ESS functionality (CANNOT disable)",
        env="NETSEC_ESS_ENABLED",
        locked=True
    )
    require_confirmation: bool = Field(
        default=True,
        description="Require confirmation before activation",
        env="NETSEC_ESS_CONFIRM"
    )
    auto_lock_evidence: bool = Field(
        default=True,
        description="Automatically lock evidence on ESS",
        env="NETSEC_ESS_LOCK_EVIDENCE"
    )
    recovery_requires_admin: bool = Field(
        default=True,
        description="Require admin role for recovery",
        env="NETSEC_ESS_RECOVERY_ADMIN"
    )


# ============================================================================
# MASTER CONFIGURATION SCHEMA
# ============================================================================

class ConfigurationSchema(BaseModel):
    """
    Complete configuration schema for NetSec Platform
    
    This is the canonical source of truth for all configuration options.
    Every field here corresponds to actual backend functionality.
    """
    
    # Application
    app: AppConfig = Field(default_factory=AppConfig)
    
    # Network
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    
    # Capture
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    
    # Evidence
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    
    # Authentication
    auth: AuthConfig = Field(default_factory=AuthConfig)
    
    # Audit
    audit: AuditConfig = Field(default_factory=AuditConfig)
    
    # Testing
    testing: TestingConfig = Field(default_factory=TestingConfig)
    
    # Emergency Stop
    ess: ESSConfig = Field(default_factory=ESSConfig)

    class Config:
        arbitrary_types_allowed = True
        use_enum_values = True


# ============================================================================
# METADATA FOR UI GENERATION
# ============================================================================

CONFIG_METADATA = {
    "app.environment": {
        "category": "General",
        "restart_required": True,
        "runtime_reload": False,
        "security_critical": False,
        "description": "Deployment environment affecting defaults and behavior"
    },
    "app.log_level": {
        "category": "General",
        "restart_required": False,
        "runtime_reload": True,
        "security_critical": False,
        "description": "Verbosity of application logs"
    },
    "capture.profile": {
        "category": "Traffic Capture",
        "restart_required": True,
        "runtime_reload": False,
        "security_critical": True,
        "description": "Controls data retention: metadata_only (minimal), standard (balanced), full_evidence (complete)"
    },
    "evidence.encryption_enabled": {
        "category": "Evidence",
        "restart_required": False,
        "runtime_reload": True,
        "security_critical": True,
        "description": "Encrypt evidence at rest using AES-256-GCM"
    },
    "auth.session_timeout_minutes": {
        "category": "Authentication",
        "restart_required": False,
        "runtime_reload": True,
        "security_critical": True,
        "description": "Session expiration time in minutes"
    },
    "testing.require_authorization": {
        "category": "Authorized Pentesting",
        "restart_required": False,
        "runtime_reload": False,
        "security_critical": True,
        "locked": True,
        "description": "Require written authorization for controlled tests (cannot be disabled)"
    },
    "ess.enabled": {
        "category": "Emergency Security Stop",
        "restart_required": False,
        "runtime_reload": False,
        "security_critical": True,
        "locked": True,
        "description": "Emergency Security Stop availability (cannot be disabled)"
    }
}


def get_config_metadata(path: str) -> Dict[str, Any]:
    """Retrieve metadata for a configuration path"""
    return CONFIG_METADATA.get(path, {
        "category": "Advanced",
        "restart_required": False,
        "runtime_reload": True,
        "security_critical": False,
        "description": ""
    })


def get_all_metadata() -> Dict[str, Dict[str, Any]]:
    """Retrieve all configuration metadata"""
    return CONFIG_METADATA
