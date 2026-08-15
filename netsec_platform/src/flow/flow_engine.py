"""
Flow Engine.

Reconstructs network flows/conversations from packets.
Tracks bidirectional traffic between endpoints.
"""

import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from collections import defaultdict
import hashlib

try:
    from scapy.all import Packet, IP, IPv6, TCP, UDP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from netsec_platform.models.core_models import (
    NetworkFlow,
    TransportProtocol,
    EncryptionState,
    SecurityQuality,
    RawPacket,
    DecodedPacket,
)


logger = logging.getLogger(__name__)


class FlowEngine:
    """
    Network flow reconstruction engine.
    
    Tracks bidirectional conversations between endpoints:
    - Creates flows from packet data
    - Updates flow statistics
    - Handles TCP state tracking
    - Manages flow lifecycle
    """
    
    def __init__(
        self,
        max_flows: int = 100000,
        flow_timeout_seconds: int = 300,
    ):
        self.max_flows = max_flows
        self.flow_timeout_seconds = flow_timeout_seconds
        
        # Flow storage: flow_key -> NetworkFlow
        self._flows: Dict[str, NetworkFlow] = {}
        
        # Flow index for quick lookups
        self._flow_by_ip_port: Dict[Tuple[str, int, str, int], List[str]] = defaultdict(list)
        
        # Statistics
        self._total_flows_created = 0
        self._total_flows_expired = 0
        
        logger.info(f"FlowEngine initialized (max_flows={max_flows})")
    
    def create_flow_key(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> str:
        """Create a unique flow key (bidirectional)."""
        # Normalize to ensure bidirectional matching
        endpoints = sorted([
            (src_ip, src_port),
            (dst_ip, dst_port),
        ])
        
        key_parts = [
            endpoints[0][0],  # First IP
            str(endpoints[0][1]),  # First port
            endpoints[1][0],  # Second IP
            str(endpoints[1][1]),  # Second port
            protocol,
        ]
        
        return ":".join(key_parts)
    
    def process_packet(
        self,
        decoded_packet: DecodedPacket,
        raw_packet: Optional[RawPacket] = None,
    ) -> Optional[str]:
        """Process a packet and update/create corresponding flow."""
        metadata = decoded_packet.metadata
        
        # Extract required fields
        src_ip = metadata.get("src_ip")
        dst_ip = metadata.get("dst_ip")
        src_port = metadata.get("src_port", 0)
        dst_port = metadata.get("dst_port", 0)
        
        if not src_ip or not dst_ip:
            return None
        
        # Determine protocol
        protocols = decoded_packet.protocols
        if "TCP" in protocols:
            transport_proto = TransportProtocol.TCP
        elif "UDP" in protocols:
            transport_proto = TransportProtocol.UDP
        else:
            transport_proto = TransportProtocol.OTHER
        
        # Create flow key
        flow_key = self.create_flow_key(
            src_ip, src_port, dst_ip, dst_port, transport_proto.value
        )
        
        # Get or create flow
        if flow_key not in self._flows:
            flow = self._create_flow(
                flow_key=flow_key,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                transport_proto=transport_proto,
                timestamp=decoded_packet.timestamp,
            )
            self._flows[flow_key] = flow
            self._total_flows_created += 1
            
            # Index the flow
            self._flow_by_ip_port[(src_ip, src_port, dst_ip, dst_port)].append(flow_key)
        else:
            flow = self._flows[flow_key]
        
        # Update flow with packet info
        self._update_flow(flow, decoded_packet, raw_packet, src_ip, dst_ip)
        
        # Set flow_id on packet
        decoded_packet.flow_id = flow.flow_id
        
        return flow.flow_id
    
    def _create_flow(
        self,
        flow_key: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        transport_proto: TransportProtocol,
        timestamp: datetime,
    ) -> NetworkFlow:
        """Create a new network flow."""
        flow_id = f"flow-{flow_key}-{timestamp.timestamp()}"
        
        # Determine app protocol based on port
        app_proto = self._guess_app_protocol(dst_port)
        
        # Initial encryption state
        encryption_state = EncryptionState.UNKNOWN
        security_quality = SecurityQuality.UNKNOWN
        
        # Common encrypted ports
        if dst_port in [443, 8443, 993, 995, 465, 587]:
            encryption_state = EncryptionState.ENCRYPTED
            security_quality = SecurityQuality.GOOD
        elif dst_port in [80, 8080]:
            encryption_state = EncryptionState.PLAINTEXT
            security_quality = SecurityQuality.INSECURE
        
        flow = NetworkFlow(
            flow_id=flow_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            transport_proto=transport_proto,
            app_proto=app_proto,
            start_time=timestamp,
            first_seen=timestamp,
            last_seen=timestamp,
            encryption_state=encryption_state,
            security_quality=security_quality,
        )
        
        logger.debug(f"Created flow {flow_id}")
        return flow
    
    def _update_flow(
        self,
        flow: NetworkFlow,
        decoded_packet: DecodedPacket,
        raw_packet: Optional[RawPacket],
        src_ip: str,
        dst_ip: str,
    ):
        """Update flow with packet information."""
        timestamp = decoded_packet.timestamp
        
        # Update timing
        flow.last_seen = timestamp
        
        # Update packet count (determine direction)
        if src_ip == flow.src_ip:
            flow.packets_sent += 1
            if raw_packet:
                flow.bytes_sent += raw_packet.captured_length
        else:
            flow.packets_received += 1
            if raw_packet:
                flow.bytes_received += raw_packet.captured_length
        
        # Track packet IDs
        flow.packet_ids.append(decoded_packet.packet_id)
        
        # Update TCP state if applicable
        if flow.transport_proto == TransportProtocol.TCP:
            self._update_tcp_state(flow, decoded_packet)
        
        # Update app protocol if detected
        if decoded_packet.app_proto and not flow.app_proto:
            flow.app_proto = decoded_packet.app_proto
    
    def _update_tcp_state(self, flow: NetworkFlow, decoded_packet: DecodedPacket):
        """Track TCP connection state."""
        # Look for TCP flags in layers
        for layer in decoded_packet.layers:
            if layer.get("name") == "TCP" or "flags" in layer:
                flags = layer.get("flags", "")
                
                if "SYN" in flags and "ACK" not in flags:
                    flow.tcp_state = "SYN_SENT"
                elif "SYN" in flags and "ACK" in flags:
                    flow.tcp_state = "SYN_RECEIVED"
                elif "ACK" in flags and flow.tcp_state in ["SYN_SENT", "SYN_RECEIVED"]:
                    flow.tcp_state = "ESTABLISHED"
                elif "FIN" in flags:
                    flow.tcp_state = "FIN_WAIT"
                elif "RST" in flags:
                    flow.tcp_state = "RESET"
                
                break
    
    def _guess_app_protocol(self, port: int) -> Optional[str]:
        """Guess application protocol from port number."""
        port_map = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SUBMISSION",
            993: "IMAPS",
            995: "POP3S",
            3306: "MYSQL",
            3389: "RDP",
            5432: "POSTGRESQL",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT",
        }
        return port_map.get(port)
    
    def get_flow(self, flow_id: str) -> Optional[NetworkFlow]:
        """Get a flow by ID."""
        return self._flows.get(flow_id)
    
    def get_flows_by_endpoint(
        self,
        ip: str,
        port: Optional[int] = None,
    ) -> List[NetworkFlow]:
        """Get all flows involving a specific endpoint."""
        flows = []
        for flow in self._flows.values():
            if flow.src_ip == ip or flow.dst_ip == ip:
                if port is None or flow.src_port == port or flow.dst_port == port:
                    flows.append(flow)
        return flows
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get all active (non-expired) flows."""
        now = datetime.now(timezone.utc)
        active = []
        
        for flow in self._flows.values():
            age = (now - flow.last_seen).total_seconds()
            if age < self.flow_timeout_seconds:
                active.append(flow)
        
        return active
    
    def expire_old_flows(self) -> int:
        """Expire flows that haven't been updated recently."""
        now = datetime.now(timezone.utc)
        expired_keys = []
        
        for flow_key, flow in self._flows.items():
            age = (now - flow.last_seen).total_seconds()
            if age > self.flow_timeout_seconds:
                expired_keys.append(flow_key)
                flow.end_time = now
                flow.tcp_state = "CLOSED"
        
        # Remove expired flows
        for key in expired_keys:
            del self._flows[key]
            self._total_flows_expired += 1
        
        logger.debug(f"Expired {len(expired_keys)} flows")
        return len(expired_keys)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get flow engine statistics."""
        return {
            "total_flows_created": self._total_flows_created,
            "total_flows_expired": self._total_flows_expired,
            "active_flows": len(self._flows),
            "max_flows": self.max_flows,
            "flow_timeout_seconds": self.flow_timeout_seconds,
        }
    
    def cleanup(self):
        """Clean up resources."""
        self._flows.clear()
        self._flow_by_ip_port.clear()
        logger.info("FlowEngine cleaned up")


class NetworkFlowTracker:
    """
    High-level network flow tracker.
    
    Provides additional flow analysis capabilities:
    - Flow correlation
    - Traffic pattern analysis
    - Anomaly detection
    """
    
    def __init__(self, flow_engine: FlowEngine):
        self.flow_engine = flow_engine
        logger.info("NetworkFlowTracker initialized")
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top talking hosts by bytes."""
        ip_bytes: Dict[str, int] = defaultdict(int)
        
        for flow in self.flow_engine._flows.values():
            ip_bytes[flow.src_ip] += flow.bytes_sent
            ip_bytes[flow.dst_ip] += flow.bytes_received
        
        sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"ip": ip, "bytes": bytes_count}
            for ip, bytes_count in sorted_ips[:limit]
        ]
    
    def get_top_destinations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top destination hosts by bytes."""
        ip_bytes: Dict[str, int] = defaultdict(int)
        
        for flow in self.flow_engine._flows.values():
            ip_bytes[flow.dst_ip] += flow.bytes_sent + flow.bytes_received
        
        sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"ip": ip, "bytes": bytes_count}
            for ip, bytes_count in sorted_ips[:limit]
        ]
    
    def get_top_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top destination ports by flow count."""
        port_counts: Dict[int, int] = defaultdict(int)
        
        for flow in self.flow_engine._flows.values():
            port_counts[flow.dst_port] += 1
        
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"port": port, "count": count}
            for port, count in sorted_ports[:limit]
        ]
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect potential network anomalies."""
        anomalies = []
        
        # Check for high number of connections from single IP
        ip_connections: Dict[str, int] = defaultdict(int)
        for flow in self.flow_engine._flows.values():
            ip_connections[flow.src_ip] += 1
        
        for ip, count in ip_connections.items():
            if count > 1000:
                anomalies.append({
                    "type": "HIGH_CONNECTION_COUNT",
                    "severity": "medium",
                    "ip": ip,
                    "connection_count": count,
                    "description": f"Host {ip} has {count} connections",
                })
        
        return anomalies
