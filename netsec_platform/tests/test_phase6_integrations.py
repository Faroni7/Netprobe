"""
Tests for Phase 6: Kubernetes and Cloud VPC Integrations
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Test data models
try:
    from netsec_platform.integrations.kubernetes import (
        KubernetesPod,
        KubernetesService,
        KubernetesNetworkPolicy,
        KubernetesFlow,
        PodPhase,
        ServiceType,
        K8sResourceType
    )
    K8S_IMPORT_OK = True
except ImportError as e:
    K8S_IMPORT_OK = False
    print(f"Kubernetes import error (expected if kubernetes lib not installed): {e}")

try:
    from netsec_platform.integrations.cloud_vpc import (
        VPCFlowLog,
        FlowDirection,
        FlowAction,
        CloudProvider,
        TransportProtocol
    )
    VPC_IMPORT_OK = True
except ImportError as e:
    VPC_IMPORT_OK = False
    print(f"VPC import error: {e}")

try:
    from netsec_platform.models.core_models import (
        NetworkFlow,
        IPAddress,
        SecurityFinding,
        FindingSeverity,
        FindingConfidence,
        TransportProtocol as CoreTransportProtocol
    )
    MODELS_IMPORT_OK = True
except ImportError as e:
    MODELS_IMPORT_OK = False
    print(f"Models import error: {e}")


@pytest.mark.skipif(not K8S_IMPORT_OK, reason="Kubernetes module not available")
class TestKubernetesDataModels:
    """Test Kubernetes data models"""
    
    def test_kubernetes_pod_creation(self):
        """Test creating a Kubernetes pod"""
        pod = KubernetesPod(
            uid="pod-123",
            name="test-pod",
            namespace="default",
            node_name="node-1",
            phase=PodPhase.RUNNING,
            pod_ip="10.0.0.5",
            host_ip="192.168.1.10",
            labels={"app": "web", "tier": "frontend"},
            annotations={},
            containers=["nginx"],
            container_ips=[],
            service_account="default",
            dns_policy="ClusterFirst",
            dns_config=None,
            network_policies=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        
        assert pod.uid == "pod-123"
        assert pod.name == "test-pod"
        assert pod.namespace == "default"
        assert pod.phase == PodPhase.RUNNING
        assert pod.pod_ip == "10.0.0.5"
        assert len(pod.labels) == 2
        assert pod.labels["app"] == "web"
    
    def test_kubernetes_pod_to_dict(self):
        """Test converting pod to dictionary"""
        pod = KubernetesPod(
            uid="pod-456",
            name="api-pod",
            namespace="production",
            node_name="node-2",
            phase=PodPhase.RUNNING,
            pod_ip="10.0.0.10",
            host_ip="192.168.1.11",
            labels={"app": "api"},
            annotations={},
            containers=["api"],
            container_ips=[],
            service_account="api-sa",
            dns_policy="ClusterFirst",
            dns_config=None,
            network_policies=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        
        pod_dict = pod.to_dict()
        
        assert pod_dict["uid"] == "pod-456"
        assert pod_dict["name"] == "api-pod"
        assert pod_dict["namespace"] == "production"
        assert pod_dict["phase"] == "Running"
        assert "first_seen" in pod_dict
        assert "last_seen" in pod_dict
    
    def test_kubernetes_service_creation(self):
        """Test creating a Kubernetes service"""
        service = KubernetesService(
            uid="svc-123",
            name="web-service",
            namespace="default",
            service_type=ServiceType.CLUSTER_IP,
            cluster_ip="10.96.0.1",
            external_ips=[],
            ports=[{"name": "http", "port": 80, "target_port": 8080, "protocol": "TCP"}],
            selector={"app": "web"},
            endpoints=["10.0.0.5", "10.0.0.6"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        
        assert service.name == "web-service"
        assert service.service_type == ServiceType.CLUSTER_IP
        assert service.cluster_ip == "10.96.0.1"
        assert len(service.ports) == 1
        assert service.ports[0]["port"] == 80
    
    def test_kubernetes_network_policy_creation(self):
        """Test creating a network policy"""
        policy = KubernetesNetworkPolicy(
            uid="policy-123",
            name="deny-all",
            namespace="default",
            pod_selector={},
            policy_types=["Ingress", "Egress"],
            ingress_rules=[],
            egress_rules=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        
        assert policy.name == "deny-all"
        assert len(policy.policy_types) == 2
        assert "Ingress" in policy.policy_types


@pytest.mark.skipif(not VPC_IMPORT_OK or not MODELS_IMPORT_OK, reason="VPC module not available")
class TestCloudVPCDataModels:
    """Test Cloud VPC data models"""
    
    def test_vpc_flow_log_creation(self):
        """Test creating a VPC flow log"""
        flow_log = VPCFlowLog(
            flow_id="vpc-flow-123",
            timestamp=datetime.utcnow(),
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            src_port=45678,
            dst_port=443,
            protocol=CoreTransportProtocol.TCP,
            protocol_number=6,
            packets=100,
            bytes=5000,
            start_time=datetime.utcnow() - timedelta(seconds=60),
            end_time=datetime.utcnow(),
            direction=FlowDirection.EGRESS,
            action=FlowAction.ACCEPT,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            vpc_id="vpc-123456",
            subnet_id="subnet-789",
            instance_id="i-abc123",
            interface_id="eni-xyz789",
            account_id="123456789012",
            availability_zone="us-east-1a"
        )
        
        assert flow_log.flow_id == "vpc-flow-123"
        assert flow_log.src_ip == "10.0.0.5"
        assert flow_log.dst_port == 443
        assert flow_log.cloud_provider == CloudProvider.AWS
        assert flow_log.action == FlowAction.ACCEPT
        assert flow_log.direction == FlowDirection.EGRESS
    
    def test_vpc_flow_log_to_network_flow(self):
        """Test converting VPC flow log to NetworkFlow"""
        flow_log = VPCFlowLog(
            flow_id="vpc-flow-456",
            timestamp=datetime.utcnow(),
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            src_port=45678,
            dst_port=80,
            protocol=CoreTransportProtocol.TCP,
            protocol_number=6,
            packets=50,
            bytes=2500,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            direction=FlowDirection.EGRESS,
            action=FlowAction.ACCEPT,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            vpc_id="vpc-123",
            subnet_id=None,
            instance_id=None,
            interface_id=None,
            account_id=None,
            availability_zone=None
        )
        
        network_flow = flow_log.to_network_flow()
        
        assert network_flow.fid == "vpc-flow-456"
        assert str(network_flow.src_ip) == "10.0.0.5"
        assert str(network_flow.dst_ip) == "10.0.0.10"
        assert network_flow.dst_port == 80
        # Egress means sent
        assert network_flow.packets_sent == 50
        assert network_flow.bytes_sent == 2500
    
    def test_vpc_flow_log_ingress_direction(self):
        """Test VPC flow log with ingress direction"""
        flow_log = VPCFlowLog(
            flow_id="vpc-flow-789",
            timestamp=datetime.utcnow(),
            src_ip="203.0.113.50",
            dst_ip="10.0.0.5",
            src_port=12345,
            dst_port=22,
            protocol=CoreTransportProtocol.TCP,
            protocol_number=6,
            packets=10,
            bytes=500,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            direction=FlowDirection.INGRESS,
            action=FlowAction.ACCEPT,
            cloud_provider=CloudProvider.AZURE,
            region="eastus",
            vpc_id="vnet-123",
            subnet_id=None,
            instance_id=None,
            interface_id=None,
            account_id=None,
            availability_zone=None
        )
        
        network_flow = flow_log.to_network_flow()
        
        # Ingress means received
        assert network_flow.packets_received == 10
        assert network_flow.bytes_received == 500
    
    def test_vpc_flow_log_to_dict(self):
        """Test converting VPC flow log to dictionary"""
        flow_log = VPCFlowLog(
            flow_id="vpc-flow-dict",
            timestamp=datetime.utcnow(),
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            src_port=45678,
            dst_port=443,
            protocol=CoreTransportProtocol.TCP,
            protocol_number=6,
            packets=100,
            bytes=5000,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            direction=FlowDirection.EGRESS,
            action=FlowAction.ACCEPT,
            cloud_provider=CloudProvider.AWS,
            region="us-east-1",
            vpc_id="vpc-123",
            subnet_id="subnet-456",
            instance_id="i-abc",
            interface_id="eni-xyz",
            account_id="123456789",
            availability_zone="us-east-1a"
        )
        
        flow_dict = flow_log.to_dict()
        
        assert flow_dict["flow_id"] == "vpc-flow-dict"
        assert flow_dict["src_ip"] == "10.0.0.5"
        assert flow_dict["dst_port"] == 443
        assert flow_dict["cloud_provider"] == "AWS"
        assert flow_dict["direction"] == "egress"
        assert flow_dict["action"] == "ACCEPT"
        assert "timestamp" in flow_dict


class TestCloudProviderEnum:
    """Test CloudProvider enum"""
    
    def test_cloud_provider_values(self):
        """Test cloud provider enum values"""
        if VPC_IMPORT_OK:
            assert CloudProvider.AWS.value == "AWS"
            assert CloudProvider.AZURE.value == "Azure"
            assert CloudProvider.GCP.value == "GCP"
            assert CloudProvider.UNKNOWN.value == "Unknown"


class TestFlowDirectionEnum:
    """Test FlowDirection enum"""
    
    def test_flow_direction_values(self):
        """Test flow direction enum values"""
        if VPC_IMPORT_OK:
            assert FlowDirection.INGRESS.value == "ingress"
            assert FlowDirection.EGRESS.value == "egress"
            assert FlowDirection.UNKNOWN.value == "unknown"


class TestFlowActionEnum:
    """Test FlowAction enum"""
    
    def test_flow_action_values(self):
        """Test flow action enum values"""
        if VPC_IMPORT_OK:
            assert FlowAction.ACCEPT.value == "ACCEPT"
            assert FlowAction.REJECT.value == "REJECT"
            assert FlowAction.DROP.value == "DROP"
            assert FlowAction.UNKNOWN.value == "UNKNOWN"


class TestPodPhaseEnum:
    """Test PodPhase enum"""
    
    def test_pod_phase_values(self):
        """Test pod phase enum values"""
        if K8S_IMPORT_OK:
            assert PodPhase.PENDING.value == "Pending"
            assert PodPhase.RUNNING.value == "Running"
            assert PodPhase.SUCCEEDED.value == "Succeeded"
            assert PodPhase.FAILED.value == "Failed"
            assert PodPhase.UNKNOWN.value == "Unknown"


class TestServiceTypeEnum:
    """Test ServiceType enum"""
    
    def test_service_type_values(self):
        """Test service type enum values"""
        if K8S_IMPORT_OK:
            assert ServiceType.CLUSTER_IP.value == "ClusterIP"
            assert ServiceType.NODE_PORT.value == "NodePort"
            assert ServiceType.LOAD_BALANCER.value == "LoadBalancer"
            assert ServiceType.EXTERNAL_NAME.value == "ExternalName"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
