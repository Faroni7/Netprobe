"""
NetSec Platform - Cloud VPC Flow Log Adapters

Provides visibility into cloud network traffic through flow logs:
- AWS VPC Flow Logs
- Azure VNet Flow Logs  
- GCP VPC Flow Logs
- Normalized flow model for cross-cloud analysis

Note: Cloud flow logs provide metadata only (no packet payloads)
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, AsyncIterator
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient
    from azure.mgmt.network import NetworkManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import logging as gcp_logging
    from google.cloud import storage as gcp_storage
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from ..models.core_models import (
    NetworkFlow, IPAddress, TransportProtocol, 
    EncryptionState, SecurityFinding, FindingSeverity, FindingConfidence
)
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"
    UNKNOWN = "Unknown"


class FlowDirection(Enum):
    """Flow direction"""
    INGRESS = "ingress"
    EGRESS = "egress"
    UNKNOWN = "unknown"


class FlowAction(Enum):
    """Flow action decision"""
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    DROP = "DROP"
    UNKNOWN = "UNKNOWN"


@dataclass
class VPCFlowLog:
    """Normalized VPC flow log entry"""
    flow_id: str
    timestamp: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[TransportProtocol]
    protocol_number: int
    packets: int
    bytes: int
    start_time: datetime
    end_time: datetime
    direction: FlowDirection
    action: FlowAction
    cloud_provider: CloudProvider
    region: str
    vpc_id: str
    subnet_id: Optional[str]
    instance_id: Optional[str]
    interface_id: Optional[str]
    account_id: Optional[str]
    availability_zone: Optional[str]
    tcp_flags: Optional[int]
    rule_id: Optional[str]
    security_group_id: Optional[str]
    raw_log: Dict[str, Any] = field(default_factory=dict)
    
    def to_network_flow(self) -> NetworkFlow:
        """Convert to standard NetworkFlow model"""
        return NetworkFlow(
            fid=self.flow_id,
            src_ip=IPAddress(self.src_ip) if self.src_ip else None,
            src_port=self.src_port,
            dst_ip=IPAddress(self.dst_ip) if self.dst_ip else None,
            dst_port=self.dst_port,
            proto=self.protocol or TransportProtocol.UNKNOWN,
            packets_sent=self.packets if self.direction == FlowDirection.EGRESS else 0,
            packets_received=self.packets if self.direction == FlowDirection.INGRESS else 0,
            bytes_sent=self.bytes if self.direction == FlowDirection.EGRESS else 0,
            bytes_received=self.bytes if self.direction == FlowDirection.INGRESS else 0,
            start_time=self.start_time,
            end_time=self.end_time,
            encryption_state=EncryptionState.UNKNOWN
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value if self.protocol else None,
            "protocol_number": self.protocol_number,
            "packets": self.packets,
            "bytes": self.bytes,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "direction": self.direction.value,
            "action": self.action.value,
            "cloud_provider": self.cloud_provider.value,
            "region": self.region,
            "vpc_id": self.vpc_id,
            "subnet_id": self.subnet_id,
            "instance_id": self.instance_id,
            "interface_id": self.interface_id,
            "account_id": self.account_id,
            "availability_zone": self.availability_zone,
            "tcp_flags": self.tcp_flags,
            "rule_id": self.rule_id,
            "security_group_id": self.security_group_id
        }


class CloudVPCAdapter(ABC):
    """Abstract base class for cloud VPC flow log adapters"""
    
    def __init__(self, subscription_id: Optional[str] = None):
        self.subscription_id = subscription_id
        self.connected = False
        self.flow_buffer: List[VPCFlowLog] = []
        self.processed_flows: Set[str] = set()
        
    @abstractmethod
    async def connect(self) -> bool:
        """Connect to cloud provider"""
        pass
    
    @abstractmethod
    async def fetch_flow_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]] = None,
        region: Optional[str] = None
    ) -> AsyncIterator[VPCFlowLog]:
        """Fetch flow logs from cloud provider"""
        pass
    
    @abstractmethod
    def parse_flow_log(self, raw_log: Dict[str, Any]) -> Optional[VPCFlowLog]:
        """Parse raw flow log into normalized format"""
        pass
    
    def get_provider(self) -> CloudProvider:
        """Get cloud provider"""
        return CloudProvider.UNKNOWN
    
    async def stream_flows(
        self,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]] = None,
        batch_size: int = 1000
    ) -> AsyncIterator[VPCFlowLog]:
        """Stream flow logs with buffering"""
        async for flow in self.fetch_flow_logs(start_time, end_time, vpc_ids):
            if flow.flow_id not in self.processed_flows:
                self.processed_flows.add(flow.flow_id)
                yield flow
                
                # Limit buffer size
                if len(self.processed_flows) > 100000:
                    # Clear old processed flows
                    oldest = list(self.processed_flows)[:50000]
                    for fid in oldest:
                        self.processed_flows.discard(fid)
    
    def analyze_flow_for_findings(self, flow: VPCFlowLog) -> List[SecurityFinding]:
        """Analyze flow for security findings"""
        findings = []
        
        # Check for rejected/dropped traffic
        if flow.action in [FlowAction.REJECT, FlowAction.DROP]:
            findings.append(SecurityFinding(
                title=f"Cloud Network Traffic {flow.action.value}",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                description=f"Traffic from {flow.src_ip} to {flow.dst_ip}:{flow.dst_port} was {flow.action.value}",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                proto=flow.protocol,
                evidence_references=[flow.flow_id],
                remediation="Review security group/NACL rules if this traffic should be allowed"
            ))
        
        # Check for unusual ports
        unusual_ports = {22, 23, 3389, 5900}  # SSH, Telnet, RDP, VNC
        if flow.dst_port in unusual_ports and flow.action == FlowAction.ACCEPT:
            findings.append(SecurityFinding(
                title="Sensitive Service Access Detected",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                description=f"Access to sensitive port {flow.dst_port} detected",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                proto=flow.protocol,
                evidence_references=[flow.flow_id],
                remediation="Verify this access is authorized and necessary"
            ))
        
        return findings


class AWSVPCAdapter(CloudVPCAdapter):
    """AWS VPC Flow Logs adapter"""
    
    def __init__(self, aws_access_key: Optional[str] = None, aws_secret_key: Optional[str] = None, region: str = "us-east-1"):
        super().__init__()
        if not AWS_AVAILABLE:
            raise ImportError("boto3 not installed. Install with: pip install boto3")
        
        self.region = region
        self.logs_client = None
        self.s3_client = None
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        
    def get_provider(self) -> CloudProvider:
        return CloudProvider.AWS
    
    async def connect(self) -> bool:
        """Connect to AWS"""
        try:
            if self.aws_access_key and self.aws_secret_key:
                self.logs_client = boto3.client(
                    'logs',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                    region_name=self.region
                )
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                    region_name=self.region
                )
            else:
                # Use default credential chain
                self.logs_client = boto3.client('logs', region_name=self.region)
                self.s3_client = boto3.client('s3', region_name=self.region)
            
            # Test connection
            self.logs_client.describe_log_groups(limit=1)
            
            self.connected = True
            logger.info("Connected to AWS", extra={"region": self.region})
            return True
            
        except Exception as e:
            logger.error("Failed to connect to AWS", extra={"error": str(e)})
            return False
    
    async def fetch_flow_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]] = None,
        region: Optional[str] = None
    ) -> AsyncIterator[VPCFlowLog]:
        """Fetch AWS VPC Flow Logs"""
        if not self.connected:
            return
        
        # AWS Flow Logs are typically stored in CloudWatch Logs or S3
        # This is a simplified example - production would need proper log group discovery
        
        log_groups = []
        try:
            response = self.logs_client.describe_log_groups(logGroupNamePrefix='flow-logs')
            log_groups = [lg['logGroupName'] for lg in response.get('logGroups', [])]
        except ClientError as e:
            logger.error("Failed to describe log groups", extra={"error": str(e)})
            return
        
        for log_group in log_groups:
            try:
                paginator = self.logs_client.get_paginator('filter_log_events')
                
                for page in paginator.paginate(
                    logGroupName=log_group,
                    startTime=int(start_time.timestamp() * 1000),
                    endTime=int(end_time.timestamp() * 1000),
                    filterPattern='- "-"'  # Exclude rejected if desired
                ):
                    for event in page.get('events', []):
                        message = json.loads(event.get('message', '{}'))
                        flow = self.parse_flow_log(message)
                        if flow:
                            yield flow
                            
            except ClientError as e:
                logger.error("Failed to fetch flow logs", extra={
                    "log_group": log_group,
                    "error": str(e)
                })
    
    def parse_flow_log(self, raw_log: Dict[str, Any]) -> Optional[VPCFlowLog]:
        """Parse AWS VPC Flow Log record"""
        try:
            # AWS flow log format varies by version
            # Example: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
            
            message = raw_log.get('message', '')
            if isinstance(message, str):
                parts = message.split()
                if len(parts) < 12:
                    return None
                
                version = parts[0]
                account_id = parts[1]
                interface_id = parts[2]
                srcaddr = parts[3] if parts[3] != '-' else None
                dstaddr = parts[4] if parts[4] != '-' else None
                srcport = int(parts[5]) if parts[5] != '-' else None
                dstport = int(parts[6]) if parts[6] != '-' else None
                protocol_num = int(parts[7]) if parts[7] != '-' else 0
                packets = int(parts[8]) if parts[8] != '-' else 0
                bytes_count = int(parts[9]) if parts[9] != '-' else 0
                start = int(parts[10]) if parts[10] != '-' else 0
                end = int(parts[11]) if parts[11] != '-' else 0
                action = parts[12] if len(parts) > 12 else 'UNKNOWN'
                
                # Map protocol number
                protocol = self._map_protocol(protocol_num)
                
                # Map action
                flow_action = FlowAction.ACCEPT if action == 'ACCEPT' else (FlowAction.REJECT if action == 'REJECT' else FlowAction.DROP)
                
                return VPCFlowLog(
                    flow_id=f"aws-{interface_id}-{start}-{end}",
                    timestamp=datetime.utcnow(),
                    src_ip=srcaddr,
                    dst_ip=dstaddr,
                    src_port=srcport,
                    dst_port=dstport,
                    protocol=protocol,
                    protocol_number=protocol_num,
                    packets=packets,
                    bytes=bytes_count,
                    start_time=datetime.fromtimestamp(start),
                    end_time=datetime.fromtimestamp(end),
                    direction=FlowDirection.UNKNOWN,
                    action=flow_action,
                    cloud_provider=CloudProvider.AWS,
                    region=self.region,
                    vpc_id="",  # Would need to lookup from interface
                    subnet_id=None,
                    instance_id=None,
                    interface_id=interface_id,
                    account_id=account_id,
                    availability_zone=None,
                    tcp_flags=None,
                    rule_id=None,
                    security_group_id=None,
                    raw_log=raw_log
                )
                
        except Exception as e:
            logger.debug("Failed to parse AWS flow log", extra={"error": str(e)})
            return None
        
        return None
    
    def _map_protocol(self, protocol_num: int) -> TransportProtocol:
        """Map IP protocol number to TransportProtocol"""
        mapping = {
            1: TransportProtocol.ICMP,
            6: TransportProtocol.TCP,
            17: TransportProtocol.UDP,
            47: TransportProtocol.GRE,
            50: TransportProtocol.ESP,
            51: TransportProtocol.AH,
        }
        return mapping.get(protocol_num, TransportProtocol.UNKNOWN)


class AzureVNetAdapter(CloudVPCAdapter):
    """Azure VNet Flow Logs adapter"""
    
    def __init__(self, subscription_id: Optional[str] = None, tenant_id: Optional[str] = None):
        super().__init__(subscription_id)
        if not AZURE_AVAILABLE:
            raise ImportError("azure libraries not installed. Install with: pip install azure-identity azure-storage-blob azure-mgmt-network")
        
        self.tenant_id = tenant_id
        self.credential = None
        self.network_client = None
        self.blob_client = None
        
    def get_provider(self) -> CloudProvider:
        return CloudProvider.AZURE
    
    async def connect(self) -> bool:
        """Connect to Azure"""
        try:
            self.credential = DefaultAzureCredential()
            
            if self.subscription_id:
                self.network_client = NetworkManagementClient(
                    credential=self.credential,
                    subscription_id=self.subscription_id
                )
                
                self.connected = True
                logger.info("Connected to Azure", extra={"subscription_id": self.subscription_id})
                return True
            else:
                logger.error("No subscription ID provided")
                return False
                
        except Exception as e:
            logger.error("Failed to connect to Azure", extra={"error": str(e)})
            return False
    
    async def fetch_flow_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]] = None,
        region: Optional[str] = None
    ) -> AsyncIterator[VPCFlowLog]:
        """Fetch Azure VNet Flow Logs"""
        if not self.connected:
            return
        
        # Azure flow logs are stored in storage accounts
        # This is simplified - production would enumerate NSGs and their flow logs
        
        try:
            # List all Network Watchers
            watchers = list(self.network_client.network_watchers.list_all())
            
            for watcher in watchers:
                # Get flow log configuration for each NSG
                # In production, would fetch actual logs from storage
                pass
                
        except Exception as e:
            logger.error("Failed to fetch Azure flow logs", extra={"error": str(e)})
    
    def parse_flow_log(self, raw_log: Dict[str, Any]) -> Optional[VPCFlowLog]:
        """Parse Azure flow log record"""
        try:
            # Azure flow log JSON format
            system = raw_log.get('systemId', '')
            mac_address = raw_log.get('macAddress', '').upper()
            
            flows = raw_log.get('flows', [])
            for flow in flows:
                rule = flow.get('rule', '')
                direction = flow.get('direction', 'Inbound')
                
                flow_tuples = flow.get('flowTuples', [])
                for tuple_str in flow_tuples:
                    parts = tuple_str.split(',')
                    if len(parts) >= 7:
                        timestamp = int(parts[0])
                        src_ip = parts[1]
                        dst_ip = parts[2]
                        src_port = int(parts[3])
                        dst_port = int(parts[4])
                        protocol = parts[5]
                        action = parts[6]
                        
                        return VPCFlowLog(
                            flow_id=f"azure-{mac_address}-{timestamp}",
                            timestamp=datetime.fromtimestamp(timestamp),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=TransportProtocol.TCP if protocol == 'T' else TransportProtocol.UDP,
                            protocol_number=6 if protocol == 'T' else 17,
                            packets=0,
                            bytes=0,
                            start_time=datetime.fromtimestamp(timestamp),
                            end_time=datetime.fromtimestamp(timestamp),
                            direction=FlowDirection.INGRESS if direction == 'Inbound' else FlowDirection.EGRESS,
                            action=FlowAction.ACCEPT if action == 'A' else FlowAction.DROP,
                            cloud_provider=CloudProvider.AZURE,
                            region="",
                            vpc_id="",
                            subnet_id=None,
                            instance_id=None,
                            interface_id=mac_address,
                            account_id=system,
                            availability_zone=None,
                            tcp_flags=None,
                            rule_id=rule,
                            security_group_id=None,
                            raw_log=raw_log
                        )
                        
        except Exception as e:
            logger.debug("Failed to parse Azure flow log", extra={"error": str(e)})
            return None
        
        return None


class GCPVPCAdapter(CloudVPCAdapter):
    """GCP VPC Flow Logs adapter"""
    
    def __init__(self, project_id: Optional[str] = None, credentials_path: Optional[str] = None):
        super().__init__(project_id)
        if not GCP_AVAILABLE:
            raise ImportError("google-cloud libraries not installed. Install with: pip install google-cloud-logging google-cloud-storage")
        
        self.project_id = project_id
        self.credentials_path = credentials_path
        self.logging_client = None
        
    def get_provider(self) -> CloudProvider:
        return CloudProvider.GCP
    
    async def connect(self) -> bool:
        """Connect to GCP"""
        try:
            self.logging_client = gcp_logging.Client(project=self.project_id)
            
            # Test connection
            list(self.logging_client.list_entries(max_results=1))
            
            self.connected = True
            logger.info("Connected to GCP", extra={"project_id": self.project_id})
            return True
            
        except Exception as e:
            logger.error("Failed to connect to GCP", extra={"error": str(e)})
            return False
    
    async def fetch_flow_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]] = None,
        region: Optional[str] = None
    ) -> AsyncIterator[VPCFlowLog]:
        """Fetch GCP VPC Flow Logs"""
        if not self.connected:
            return
        
        try:
            # Filter for VPC flow logs
            filter_str = f'timestamp>="{start_time.isoformat()}Z" timestamp<="{end_time.isoformat()}Z" resource.type="gce_subnetwork"'
            
            if vpc_ids:
                vpc_filter = ' OR '.join([f'resource.labels.subnetwork_id="{vpc}"' for vpc in vpc_ids])
                filter_str += f' AND ({vpc_filter})'
            
            entries = self.logging_client.list_entries(filter_=filter_str, max_results=1000)
            
            for entry in entries:
                payload = entry.payload
                if payload:
                    flow = self.parse_flow_log(payload)
                    if flow:
                        yield flow
                        
        except Exception as e:
            logger.error("Failed to fetch GCP flow logs", extra={"error": str(e)})
    
    def parse_flow_log(self, raw_log: Dict[str, Any]) -> Optional[VPCFlowLog]:
        """Parse GCP flow log record"""
        try:
            # GCP flow log format
            connection = raw_log.get('connection', {})
            
            src_ip = connection.get('src_ip')
            dst_ip = connection.get('dest_ip')
            src_port = connection.get('src_port')
            dst_port = connection.get('dest_port')
            protocol = connection.get('protocol')  # TCP or UDP
            
            bytes_sent = raw_log.get('bytes_sent', 0)
            bytes_received = raw_log.get('bytes_received', 0)
            packets_sent = raw_log.get('packets_sent', 0)
            packets_received = raw_log.get('packets_received', 0)
            
            start_time = raw_log.get('start_time')
            end_time = raw_log.get('end_time')
            
            action = raw_log.get('action', 'allow')
            direction = raw_log.get('direction', 'UNKNOWN')
            
            # Extract metadata
            metadata = raw_log.get('metadata', {})
            vm_instance = metadata.get('vm_instance', '')
            subnetwork = metadata.get('subnetwork', '')
            region = metadata.get('region', '')
            
            # Parse timestamps
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            
            return VPCFlowLog(
                flow_id=f"gcp-{subnetwork}-{start_time}",
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=TransportProtocol.TCP if protocol == 'TCP' else TransportProtocol.UDP,
                protocol_number=6 if protocol == 'TCP' else 17,
                packets=packets_sent + packets_received,
                bytes=bytes_sent + bytes_received,
                start_time=start_time if isinstance(start_time, datetime) else datetime.utcnow(),
                end_time=end_time if isinstance(end_time, datetime) else datetime.utcnow(),
                direction=FlowDirection.INGRESS if direction == 'INGRESS' else FlowDirection.EGRESS,
                action=FlowAction.ACCEPT if action == 'allow' else FlowAction.DROP,
                cloud_provider=CloudProvider.GCP,
                region=region,
                vpc_id=subnetwork,
                subnet_id=subnetwork,
                instance_id=vm_instance,
                interface_id=None,
                account_id=self.project_id,
                availability_zone=None,
                tcp_flags=None,
                rule_id=None,
                security_group_id=None,
                raw_log=raw_log
            )
            
        except Exception as e:
            logger.debug("Failed to parse GCP flow log", extra={"error": str(e)})
            return None


class MultiCloudFlowAggregator:
    """Aggregates flow logs from multiple cloud providers"""
    
    def __init__(self):
        self.adapters: Dict[CloudProvider, CloudVPCAdapter] = {}
        self.aggregated_flows: List[VPCFlowLog] = []
        
    def add_adapter(self, adapter: CloudVPCAdapter):
        """Add a cloud provider adapter"""
        provider = adapter.get_provider()
        self.adapters[provider] = adapter
        logger.info("Added cloud adapter", extra={"provider": provider.value})
    
    async def fetch_all_flows(
        self,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]] = None
    ) -> AsyncIterator[VPCFlowLog]:
        """Fetch flows from all connected cloud providers"""
        tasks = []
        
        for provider, adapter in self.adapters.items():
            if adapter.connected:
                task = asyncio.create_task(
                    self._fetch_from_adapter(adapter, start_time, end_time, vpc_ids)
                )
                tasks.append(task)
        
        # Aggregate results from all providers
        for task in asyncio.as_completed(tasks):
            try:
                flows = await task
                for flow in flows:
                    yield flow
            except Exception as e:
                logger.error("Error fetching flows from provider", extra={"error": str(e)})
    
    async def _fetch_from_adapter(
        self,
        adapter: CloudVPCAdapter,
        start_time: datetime,
        end_time: datetime,
        vpc_ids: Optional[List[str]]
    ) -> List[VPCFlowLog]:
        """Fetch flows from a single adapter"""
        flows = []
        async for flow in adapter.stream_flows(start_time, end_time, vpc_ids):
            flows.append(flow)
            self.aggregated_flows.append(flow)
        return flows
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of aggregated flows"""
        by_provider = {}
        by_region = {}
        by_vpc = {}
        
        for flow in self.aggregated_flows:
            # By provider
            provider = flow.cloud_provider.value
            by_provider[provider] = by_provider.get(provider, 0) + 1
            
            # By region
            region = flow.region or "unknown"
            by_region[region] = by_region.get(region, 0) + 1
            
            # By VPC
            vpc = flow.vpc_id or "unknown"
            by_vpc[vpc] = by_vpc.get(vpc, 0) + 1
        
        return {
            "total_flows": len(self.aggregated_flows),
            "by_provider": by_provider,
            "by_region": by_region,
            "by_vpc": by_vpc,
            "adapters_connected": len([a for a in self.adapters.values() if a.connected])
        }


# Example usage
async def example_cloud_integration():
    """Example of integrating cloud flow logs"""
    
    # Create adapters for each cloud provider
    aggregator = MultiCloudFlowAggregator()
    
    # AWS
    if AWS_AVAILABLE:
        aws_adapter = AWSVPCAdapter(region="us-east-1")
        if await aws_adapter.connect():
            aggregator.add_adapter(aws_adapter)
    
    # Azure
    if AZURE_AVAILABLE:
        azure_adapter = AzureVNetAdapter(subscription_id="your-subscription-id")
        if await azure_adapter.connect():
            aggregator.add_adapter(azure_adapter)
    
    # GCP
    if GCP_AVAILABLE:
        gcp_adapter = GCPVPCAdapter(project_id="your-project-id")
        if await gcp_adapter.connect():
            aggregator.add_adapter(gcp_adapter)
    
    # Fetch flows from last hour
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=1)
    
    print(f"Fetching flows from {start_time} to {end_time}")
    
    async for flow in aggregator.fetch_all_flows(start_time, end_time):
        print(f"Flow: {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} ({flow.cloud_provider.value})")
    
    # Get summary
    summary = aggregator.get_summary()
    print(f"Summary: {json.dumps(summary, indent=2)}")


if __name__ == "__main__":
    asyncio.run(example_cloud_integration())
