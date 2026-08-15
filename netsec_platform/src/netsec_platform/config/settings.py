"""
Configuration management for the NetSec Platform.

Handles all configuration aspects including:
- Capture profiles (Metadata Only, Standard, Full Evidence)
- Storage settings and encryption
- Emergency Security Stop (ESS) settings
- Authorization and scope controls
- Retention policies
"""

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from typing import Optional, List, Set
from enum import Enum
from datetime import timedelta


class CaptureProfileEnum(str, Enum):
    """Capture profile types defining what data is retained."""
    METADATA_ONLY = "metadata_only"  # Profile A - No payloads
    STANDARD = "standard"  # Profile B - Recommended default
    FULL_EVIDENCE = "full_evidence"  # Profile C - Full payload capture


class StorageConfig(BaseModel):
    """Configuration for evidence and data storage."""
    base_path: str = "/var/netsec_platform/data"
    pcap_path: str = "pcaps"
    evidence_path: str = "evidence"
    db_path: str = "db/netsec.db"
    log_path: str = "logs"
    
    # Retention settings
    metadata_retention_days: int = 30
    pcap_retention_days: int = 7
    evidence_retention_days: int = 90
    
    # Storage limits
    max_storage_gb: float = 100.0
    max_pcap_size_mb: float = 1024.0
    
    # Encryption settings
    encrypt_evidence_at_rest: bool = True
    encryption_key_path: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "base_path": "/var/netsec_platform/data",
                "encrypt_evidence_at_rest": True,
                "max_storage_gb": 100.0
            }
        }


class CaptureConfig(BaseModel):
    """Configuration for packet capture engine."""
    profile: CaptureProfileEnum = CaptureProfileEnum.STANDARD
    
    # Interface settings
    interface: Optional[str] = None
    snap_length: int = 65535
    
    # Buffer and performance
    ring_buffer_size_mb: int = 512
    max_packets_per_second: int = 100000
    
    # Filters
    bpf_filter: Optional[str] = None
    
    # Limits
    max_capture_size_mb: float = 4096.0
    max_capture_duration_hours: int = 24
    
    class Config:
        json_schema_extra = {
            "example": {
                "profile": "standard",
                "snap_length": 65535,
                "max_capture_size_mb": 4096.0
            }
        }


class ScopeConfig(BaseModel):
    """Authorization scope configuration for controlled testing."""
    allowed_ips: List[str] = Field(default_factory=list)
    allowed_cidrs: List[str] = Field(default_factory=list)
    excluded_ips: List[str] = Field(default_factory=list)
    excluded_cidrs: List[str] = Field(default_factory=list)
    
    allowed_domains: List[str] = Field(default_factory=list)
    excluded_domains: List[str] = Field(default_factory=list)
    
    allowed_ports: List[int] = Field(default_factory=list)
    excluded_ports: List[int] = Field(default_factory=list)
    
    # Authorization reference
    auth_reference: Optional[str] = None
    authz_type: str = "written_authorization"
    
    # Testing period
    testing_start: Optional[str] = None
    testing_end: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "allowed_cidrs": ["10.10.0.0/16"],
                "excluded_cidrs": ["10.10.50.0/24"],
                "allowed_domains": ["portal.example.com", "api.example.com"],
                "auth_reference": "AUTH-2026-0042"
            }
        }


class ESSConfig(BaseModel):
    """Emergency Security Stop configuration."""
    enabled: bool = True
    require_confirmation: bool = True
    lock_sensitive_evidence: bool = True
    stop_active_tests: bool = True
    stop_exports: bool = True
    preserve_evidence: bool = True
    
    # Recovery settings
    require_auth_for_recovery: bool = True
    auto_recovery_timeout_minutes: int = 0  # 0 = no auto recovery
    
    class Config:
        json_schema_extra = {
            "example": {
                "enabled": True,
                "require_confirmation": True,
                "lock_sensitive_evidence": True
            }
        }


class ControlledTestConfig(BaseModel):
    """Configuration for controlled security testing module."""
    enabled: bool = False
    max_requests_per_second: int = 10
    max_total_requests: int = 1000
    request_timeout_seconds: int = 30
    test_duration_limit_minutes: int = 60
    
    # Safety settings
    require_explicit_approval: bool = True
    validate_target_scope: bool = True
    fail_closed_on_error: bool = True
    
    class Config:
        json_schema_extra = {
            "example": {
                "enabled": False,
                "max_requests_per_second": 10,
                "require_explicit_approval": True
            }
        }


class NetSecConfig(BaseSettings):
    """Main application configuration."""
    
    # Application settings
    app_name: str = "NetSec Platform"
    debug: bool = False
    log_level: str = "INFO"
    
    # API settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_key: Optional[str] = None
    
    # Sub-configurations
    storage: StorageConfig = Field(default_factory=StorageConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    ess: ESSConfig = Field(default_factory=ESSConfig)
    controlled_test: ControlledTestConfig = Field(default_factory=ControlledTestConfig)
    
    # Security settings
    session_timeout_minutes: int = 60
    require_mfa: bool = False
    
    class Config:
        env_prefix = "NETSEC_"
        env_nested_delimiter = "__"
        
        json_schema_extra = {
            "example": {
                "app_name": "NetSec Platform",
                "debug": False,
                "api_host": "127.0.0.1",
                "api_port": 8000
            }
        }


def get_default_config() -> NetSecConfig:
    """Return default configuration."""
    return NetSecConfig()


def load_config(config_path: Optional[str] = None) -> NetSecConfig:
    """Load configuration from file or environment."""
    if config_path:
        return NetSecConfig(_env_file=config_path)
    return NetSecConfig()
