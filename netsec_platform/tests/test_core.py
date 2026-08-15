"""
Tests for the NetSec Platform core components.

These tests verify:
- Configuration management
- Emergency Security Stop (ESS)
- Core data models
- Logging configuration
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from netsec_platform.config.settings import (
    NetSecConfig,
    CaptureProfileEnum,
    ESSConfig,
    StorageConfig,
)
from netsec_platform.utils.emergency_stop import (
    EmergencySecurityStop,
    ESSState,
    ESSReason,
    initialize_ess,
    get_ess,
    is_ess_active,
)
from netsec_platform.models.core_models import (
    NetworkFlow,
    TransportProtocol,
    EncryptionState,
    SecurityQuality,
    Asset,
    SensitiveArtifact,
    ArtifactType,
    DetectionConfidence,
    SecurityFinding,
    FindingSeverity,
    FindingConfidence,
    FindingStatus,
)


# ============================================================================
# Configuration Tests
# ============================================================================

class TestConfiguration:
    """Test configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = NetSecConfig()
        
        assert config.app_name == "NetSec Platform"
        assert config.debug is False
        assert config.api_host == "127.0.0.1"
        assert config.api_port == 8000
        
    def test_capture_profile_enum(self):
        """Test capture profile enumeration."""
        assert CaptureProfileEnum.METADATA_ONLY.value == "metadata_only"
        assert CaptureProfileEnum.STANDARD.value == "standard"
        assert CaptureProfileEnum.FULL_EVIDENCE.value == "full_evidence"
    
    def test_ess_config_defaults(self):
        """Test ESS configuration defaults."""
        ess_config = ESSConfig()
        
        assert ess_config.enabled is True
        assert ess_config.require_confirmation is True
        assert ess_config.lock_sensitive_evidence is True
        assert ess_config.stop_active_tests is True
    
    def test_storage_config(self):
        """Test storage configuration."""
        storage = StorageConfig()
        
        assert storage.encrypt_evidence_at_rest is True
        assert storage.max_storage_gb == 100.0
        assert storage.evidence_retention_days == 90


# ============================================================================
# Emergency Security Stop Tests
# ============================================================================

class TestEmergencySecurityStop:
    """Test Emergency Security Stop functionality."""
    
    @pytest.mark.asyncio
    async def test_ess_initialization(self):
        """Test ESS initializes correctly."""
        config = ESSConfig()
        ess = EmergencySecurityStop(config)
        
        assert ess.state == ESSState.READY
        assert ess.is_ready() is True
        assert ess.is_active() is False
    
    @pytest.mark.asyncio
    async def test_ess_activation(self):
        """Test ESS activation stops all subsystems."""
        config = ESSConfig()
        ess = EmergencySecurityStop(config)
        
        # Register mock callbacks
        stop_capture = AsyncMock()
        stop_processing = AsyncMock()
        stop_tests = AsyncMock()
        stop_exports = AsyncMock()
        lock_evidence = AsyncMock()
        
        ess.register_callbacks(
            stop_capture=stop_capture,
            stop_processing=stop_processing,
            stop_active_tests=stop_tests,
            stop_exports=stop_exports,
            lock_sensitive_evidence=lock_evidence,
        )
        
        # Activate ESS
        audit_record = await ess.activate(
            operator="test_analyst",
            reason=ESSReason.OPERATOR_REQUEST,
            reason_detail="Testing ESS activation",
        )
        
        # Verify state changes
        assert ess.state == ESSState.STOPPED
        assert ess.is_active() is True
        
        # Verify callbacks were called
        stop_capture.assert_called_once()
        stop_processing.assert_called_once()
        stop_tests.assert_called_once()
        stop_exports.assert_called_once()
        lock_evidence.assert_called_once()
        
        # Verify audit record
        assert audit_record is not None
        assert audit_record.operator == "test_analyst"
        assert audit_record.reason == ESSReason.OPERATOR_REQUEST
        assert audit_record.capture_status == "STOPPED"
    
    @pytest.mark.asyncio
    async def test_ess_recovery(self):
        """Test ESS recovery requires authorization."""
        config = ESSConfig()
        ess = EmergencySecurityStop(config)
        
        # First activate
        await ess.activate(
            operator="test_analyst",
            reason=ESSReason.OPERATOR_REQUEST,
        )
        
        assert ess.is_active() is True
        
        # Then recover
        result = await ess.recover(
            operator="senior_analyst",
            reason="False alarm, resuming operations",
        )
        
        assert result is True
        assert ess.state == ESSState.READY
        assert ess.is_ready() is True
        
        # Verify audit record updated
        audit_record = ess.get_audit_record()
        assert audit_record.recovery_operator == "senior_analyst"
    
    @pytest.mark.asyncio
    async def test_ess_operation_check(self):
        """Test operation permission checks."""
        config = ESSConfig()
        ess = EmergencySecurityStop(config)
        
        # Before activation - operations allowed
        assert ess.can_perform_operation("capture") is True
        assert ess.can_perform_operation("processing") is True
        
        # After activation - operations blocked
        await ess.activate(
            operator="test_analyst",
            reason=ESSReason.OPERATOR_REQUEST,
        )
        
        assert ess.can_perform_operation("capture") is False
        assert ess.can_perform_operation("processing") is False
    
    @pytest.mark.asyncio
    async def test_ess_global_instance(self):
        """Test global ESS instance management."""
        config = ESSConfig()
        ess = initialize_ess(config)
        
        assert get_ess() is ess
        assert is_ess_active() is False
        
        await ess.activate(
            operator="test",
            reason=ESSReason.OPERATOR_REQUEST,
        )
        
        assert is_ess_active() is True


# ============================================================================
# Core Model Tests
# ============================================================================

class TestNetworkFlow:
    """Test NetworkFlow model."""
    
    def test_flow_creation(self):
        """Test creating a network flow."""
        flow = NetworkFlow(
            flow_id="flow-001",
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="10.0.0.2",
            dst_port=443,
            transport_proto=TransportProtocol.TCP,
        )
        
        assert flow.flow_id == "flow-001"
        assert flow.transport_proto == TransportProtocol.TCP
        assert flow.encryption_state == EncryptionState.UNKNOWN
        assert flow.security_quality == SecurityQuality.UNKNOWN
    
    def test_flow_statistics(self):
        """Test flow statistics calculations."""
        flow = NetworkFlow(
            flow_id="flow-002",
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="10.0.0.2",
            dst_port=80,
            transport_proto=TransportProtocol.TCP,
            packets_sent=100,
            packets_received=150,
            bytes_sent=5000,
            bytes_received=7500,
        )
        
        assert flow.total_packets == 250
        assert flow.total_bytes == 12500
    
    def test_flow_to_dict(self):
        """Test flow serialization."""
        flow = NetworkFlow(
            flow_id="flow-003",
            src_ip="192.168.1.1",
            src_port=12345,
            dst_ip="8.8.8.8",
            dst_port=53,
            transport_proto=TransportProtocol.UDP,
            app_proto="DNS",
        )
        
        data = flow.to_dict()
        
        assert data["flow_id"] == "flow-003"
        assert data["src_ip"] == "192.168.1.1"
        assert data["dst_port"] == 53
        assert data["transport_proto"] == "UDP"
        assert data["app_proto"] == "DNS"


class TestAsset:
    """Test Asset model."""
    
    def test_asset_creation(self):
        """Test creating an asset."""
        asset = Asset(
            asset_id="host-001",
            mac_addresses=["00:11:22:33:44:55"],
            ip_addresses=["10.0.0.100"],
            hostnames=["workstation-01"],
        )
        
        assert asset.asset_id == "host-001"
        assert len(asset.mac_addresses) == 1
        assert len(asset.ip_addresses) == 1
    
    def test_asset_services(self):
        """Test asset with services."""
        asset = Asset(
            asset_id="server-001",
            ip_addresses=["10.0.0.50"],
            services=[
                {"port": 22, "proto": "TCP", "service_name": "SSH"},
                {"port": 443, "proto": "TCP", "service_name": "HTTPS"},
            ],
            open_ports=[22, 443],
        )
        
        assert len(asset.services) == 2
        assert 443 in asset.open_ports


class TestSensitiveArtifact:
    """Test SensitiveArtifact model."""
    
    def test_artifact_creation(self):
        """Test creating a sensitive artifact."""
        artifact = SensitiveArtifact(
            artifact_id="EVD-000184",
            artifact_type=ArtifactType.PASSWORD,
            field_name="password",
            src_ip="10.0.0.25",
            dst_ip="10.0.0.50",
            protocol="HTTP",
            confidence=DetectionConfidence.HIGH,
        )
        
        assert artifact.artifact_id == "EVD-000184"
        assert artifact.artifact_type == ArtifactType.PASSWORD
        assert artifact.confidence == DetectionConfidence.HIGH
        assert artifact.transport_encryption == EncryptionState.UNKNOWN
    
    def test_session_cookie_artifact(self):
        """Test session cookie artifact."""
        artifact = SensitiveArtifact(
            artifact_id="EVD-000185",
            artifact_type=ArtifactType.SESSION_COOKIE,
            field_name="SESSIONID",
            domain="portal.example.com",
            transport_encryption=EncryptionState.PLAINTEXT,
        )
        
        assert artifact.artifact_type == ArtifactType.SESSION_COOKIE
        assert artifact.transport_encryption == EncryptionState.PLAINTEXT


class TestSecurityFinding:
    """Test SecurityFinding model."""
    
    def test_finding_creation(self):
        """Test creating a security finding."""
        finding = SecurityFinding(
            finding_id="FIND-001",
            title="Plaintext Credential Exposure",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            description="Credentials transmitted over HTTP",
            remediation="Enforce HTTPS and prevent auth over plaintext HTTP",
        )
        
        assert finding.finding_id == "FIND-001"
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.status == FindingStatus.NEW
    
    def test_finding_with_evidence(self):
        """Test finding with evidence references."""
        finding = SecurityFinding(
            finding_id="FIND-002",
            title="Missing Secure Cookie Attribute",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.MEDIUM,
            evidence_ids=["EVD-000185", "EVD-000186"],
            src_ip="10.0.0.25",
            dst_ip="10.0.0.50",
        )
        
        assert len(finding.evidence_ids) == 2
        assert "EVD-000185" in finding.evidence_ids
    
    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = SecurityFinding(
            finding_id="FIND-003",
            title="Test Finding",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.LOW,
        )
        
        data = finding.to_dict()
        
        assert data["finding_id"] == "FIND-003"
        assert data["severity"] == "medium"
        assert data["confidence"] == "low"
        assert data["status"] == "new"


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for core components."""
    
    @pytest.mark.asyncio
    async def test_ess_with_config(self):
        """Test ESS integration with full config."""
        config = NetSecConfig()
        
        # Initialize ESS from config
        ess = EmergencySecurityStop(config.ess)
        
        assert ess.is_ready() is True
        
        # Activate
        await ess.activate(
            operator="admin",
            reason=ESSReason.SUSPECTED_UNAUTHORIZED_ACTIVITY,
        )
        
        assert ess.is_active() is True
        
        # Verify audit record created
        audit = ess.get_audit_record()
        assert audit is not None
        assert audit.event_type == "EMERGENCY_SECURITY_STOP"
    
    def test_flow_with_encryption_classification(self):
        """Test flow with encryption state classification."""
        # Encrypted flow
        tls_flow = NetworkFlow(
            flow_id="tls-001",
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="10.0.0.2",
            dst_port=443,
            transport_proto=TransportProtocol.TCP,
            app_proto="TLS",
            encryption_state=EncryptionState.ENCRYPTED,
            security_quality=SecurityQuality.GOOD,
        )
        
        # Plaintext flow
        http_flow = NetworkFlow(
            flow_id="http-001",
            src_ip="10.0.0.1",
            src_port=54322,
            dst_ip="10.0.0.2",
            dst_port=80,
            transport_proto=TransportProtocol.TCP,
            app_proto="HTTP",
            encryption_state=EncryptionState.PLAINTEXT,
            security_quality=SecurityQuality.INSECURE,
        )
        
        assert tls_flow.security_quality == SecurityQuality.GOOD
        assert http_flow.security_quality == SecurityQuality.INSECURE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
