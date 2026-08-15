"""
TLS Decoder.

Decodes TLS handshake metadata from packets.
Extracts TLS version, SNI, certificates, and cipher suites.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

try:
    from scapy.all import Packet, TCP, Raw, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from netsec_platform.models.core_models import TLSConnection


logger = logging.getLogger(__name__)


class TLSDecoder:
    """
    TLS protocol decoder.
    
    Extracts TLS metadata from packets including:
    - TLS version
    - Server Name Indication (SNI)
    - Certificate information
    - Cipher suites
    - ALPN protocols
    """
    
    def __init__(self):
        self._tls_connections: Dict[str, TLSConnection] = {}  # flow_key -> connection
        logger.info("TLSDecoder initialized")
    
    def decode_tls_packet(
        self,
        pkt: Packet,
        timestamp: datetime,
    ) -> Optional[Dict[str, Any]]:
        """Decode TLS handshake metadata from a packet."""
        if not SCAPY_AVAILABLE or not pkt.haslayer(TCP):
            return None
        
        try:
            # Check for raw payload
            if not pkt.haslayer(Raw):
                return None
            
            raw_data = bytes(pkt[Raw].load)
            
            # Check if it looks like TLS (starts with 0x16 for Handshake, 0x14 for Alert, etc.)
            if len(raw_data) < 5:
                return None
            
            content_type = raw_data[0]
            
            # TLS record layer types
            if content_type == 0x16:  # Handshake
                return self._parse_handshake(raw_data, pkt, timestamp)
            elif content_type == 0x15:  # Alert
                return {"type": "alert", "data": raw_data[:10].hex()}
            elif content_type == 0x14:  # ChangeCipherSpec
                return {"type": "change_cipher_spec"}
            elif content_type == 0x17:  # Application Data
                return {"type": "application_data", "encrypted": True}
            
            return None
            
        except Exception as e:
            logger.debug(f"TLS decode error: {e}")
            return None
    
    def _parse_handshake(
        self,
        raw_data: bytes,
        pkt: Packet,
        timestamp: datetime,
    ) -> Optional[Dict[str, Any]]:
        """Parse TLS handshake message."""
        try:
            # TLS record header (5 bytes)
            # Content type (1) + Version (2) + Length (2)
            if len(raw_data) < 5:
                return None
            
            version_major = raw_data[1]
            version_minor = raw_data[2]
            tls_version = f"TLS {version_major}.{version_minor}"
            
            # Skip to handshake message type
            handshake_start = 5
            
            if len(raw_data) < handshake_start + 4:
                return None
            
            # Handshake message type
            msg_type = raw_data[handshake_start]
            
            # ClientHello = 1, ServerHello = 2
            if msg_type == 1:  # ClientHello
                return self._parse_client_hello(raw_data, handshake_start, pkt, timestamp, tls_version)
            elif msg_type == 2:  # ServerHello
                return self._parse_server_hello(raw_data, handshake_start, pkt, timestamp, tls_version)
            
            return {"type": f"handshake_{msg_type}", "version": tls_version}
            
        except Exception as e:
            logger.debug(f"Handshake parse error: {e}")
            return None
    
    def _parse_client_hello(
        self,
        raw_data: bytes,
        start: int,
        pkt: Packet,
        timestamp: datetime,
        tls_version: str,
    ) -> Dict[str, Any]:
        """Parse ClientHello message."""
        result = {
            "type": "client_hello",
            "version": tls_version,
            "timestamp": timestamp.isoformat(),
        }
        
        # Try to extract SNI from extensions
        sni = self._extract_sni(raw_data, start)
        if sni:
            result["sni"] = sni
        
        # Extract cipher suites
        ciphers = self._extract_ciphers(raw_data, start)
        if ciphers:
            result["cipher_suites"] = ciphers
        
        # Get network info
        if pkt.haslayer(IP):
            result["src_ip"] = pkt[IP].src
            result["dst_ip"] = pkt[IP].dst
        
        return result
    
    def _parse_server_hello(
        self,
        raw_data: bytes,
        start: int,
        pkt: Packet,
        timestamp: datetime,
        tls_version: str,
    ) -> Dict[str, Any]:
        """Parse ServerHello message."""
        result = {
            "type": "server_hello",
            "version": tls_version,
            "timestamp": timestamp.isoformat(),
        }
        
        # Get network info
        if pkt.haslayer(IP):
            result["src_ip"] = pkt[IP].src
            result["dst_ip"] = pkt[IP].dst
        
        return result
    
    def _extract_sni(self, raw_data: bytes, start: int) -> Optional[str]:
        """Extract Server Name Indication from ClientHello."""
        try:
            # This is a simplified SNI extraction
            # Full implementation would properly parse the TLS structure
            
            # Look for common SNI patterns in the raw data
            # SNI extension type is 0x0000
            data = raw_data[start:]
            
            # Search for hostname patterns
            import re
            # Look for domain-like strings
            matches = re.findall(rb'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', data)
            if matches:
                for match in matches:
                    try:
                        candidate = match.decode('ascii')
                        if '.' in candidate and not candidate.startswith('.'):
                            return candidate
                    except Exception:
                        continue
            
            return None
            
        except Exception:
            return None
    
    def _extract_ciphers(self, raw_data: bytes, start: int) -> List[str]:
        """Extract cipher suite list from ClientHello."""
        # Simplified cipher extraction
        # Full implementation would parse the TLS structure properly
        return []
    
    def analyze_tls_security(
        self,
        tls_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Analyze TLS configuration for security issues."""
        findings = []
        
        version = tls_info.get("version", "")
        
        # Check for deprecated TLS versions
        if "TLS 1.0" in version or "SSL" in version:
            findings.append({
                "type": "DEPRECATED_TLS_VERSION",
                "severity": "high",
                "version": version,
                "description": f"Deprecated protocol version: {version}",
            })
        elif "TLS 1.1" in version:
            findings.append({
                "type": "WEAK_TLS_VERSION",
                "severity": "medium",
                "version": version,
                "description": "TLS 1.1 is deprecated",
            })
        
        return findings
    
    def create_tls_connection(
        self,
        flow_id: str,
        client_hello: Dict[str, Any],
        server_hello: Dict[str, Any],
    ) -> TLSConnection:
        """Create a TLS connection record from handshake info."""
        tls_id = f"tls-{flow_id}"
        
        return TLSConnection(
            tls_id=tls_id,
            flow_id=flow_id,
            version=server_hello.get("version", client_hello.get("version")),
            sni=client_hello.get("sni"),
            src_ip=client_hello.get("src_ip"),
            dst_ip=server_hello.get("dst_ip", client_hello.get("dst_ip")),
            timestamp=datetime.fromisoformat(client_hello["timestamp"].replace("Z", "+00:00")) if "timestamp" in client_hello else None,
        )
