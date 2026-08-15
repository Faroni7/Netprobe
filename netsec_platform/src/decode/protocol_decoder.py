"""
Protocol Decoder.

Provides modular protocol decoding for network packets.
Supports Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, and more.
"""

import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from scapy.all import (
        Packet,
        Ether,
        Dot1Q,
        ARP,
        IP,
        IPv6,
        ICMP,
        ICMPv6ND_NS,
        TCP,
        UDP,
        DNS,
        Raw,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from netsec_platform.models.core_models import DecodedPacket, RawPacket


logger = logging.getLogger(__name__)


@dataclass
class DecodedProtocol:
    """Represents a decoded protocol layer."""
    name: str
    fields: Dict[str, Any]
    summary: str = ""


class ProtocolDecoder:
    """
    Modular protocol decoder.
    
    Decodes packets through multiple protocol layers:
    - Ethernet/VLAN
    - ARP
    - IPv4/IPv6
    - TCP/UDP
    - ICMP/ICMPv6
    - Application protocols (via specialized decoders)
    """
    
    def __init__(self):
        self._decoders: Dict[str, Any] = {}
        self._supported_protocols: List[str] = [
            "Ethernet",
            "VLAN",
            "ARP",
            "IPv4",
            "IPv6",
            "TCP",
            "UDP",
            "ICMP",
            "ICMPv6",
            "GRE",
            "IP-in-IP",
        ]
        
        logger.info("ProtocolDecoder initialized")
    
    def decode_packet(self, raw_packet: RawPacket) -> Optional[DecodedPacket]:
        """Decode a raw packet into protocol layers."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, cannot decode packet")
            return None
        
        try:
            # Parse raw bytes with scapy
            pkt = Ether(raw_packet.data)
            
            layers: List[Dict[str, Any]] = []
            protocols: List[str] = []
            metadata: Dict[str, Any] = {}
            payload: Optional[bytes] = None
            
            # Walk through packet layers
            current_layer = pkt
            layer_index = 0
            
            while current_layer is not None:
                layer_info = self._decode_layer(current_layer, layer_index)
                if layer_info:
                    layers.append(layer_info["fields"])
                    protocols.append(layer_info["name"])
                    
                    # Extract key metadata
                    if layer_info["name"] == "IPv4" or layer_info["name"] == "IPv6":
                        metadata["src_ip"] = layer_info["fields"].get("src")
                        metadata["dst_ip"] = layer_info["fields"].get("dst")
                    elif layer_info["name"] == "TCP" or layer_info["name"] == "UDP":
                        metadata["src_port"] = layer_info["fields"].get("sport")
                        metadata["dst_port"] = layer_info["fields"].get("dport")
                    
                    # Check for payload
                    if current_layer.haslayer(Raw):
                        payload = bytes(current_layer[Raw].load)
                
                current_layer = current_layer.payload
                layer_index += 1
                
                # Safety limit
                if layer_index > 20:
                    logger.warning("Too many layers, stopping decode")
                    break
            
            return DecodedPacket(
                packet_id=raw_packet.packet_id,
                timestamp=raw_packet.timestamp,
                layers=layers,
                protocols=protocols,
                payload=payload,
                metadata=metadata,
            )
            
        except Exception as e:
            logger.debug(f"Failed to decode packet {raw_packet.packet_id}: {e}")
            return None
    
    def _decode_layer(self, pkt: Packet, index: int) -> Optional[Dict[str, Any]]:
        """Decode a single protocol layer."""
        try:
            if pkt is None:
                return None
            
            # Ethernet
            if pkt.haslayer(Ether) and index == 0:
                ether = pkt[Ether]
                return {
                    "name": "Ethernet",
                    "fields": {
                        "src": ether.src,
                        "dst": ether.dst,
                        "type": hex(ether.type),
                    },
                    "summary": f"Ether({ether.src} -> {ether.dst})",
                }
            
            # VLAN (802.1Q)
            if pkt.haslayer(Dot1Q):
                vlan = pkt[Dot1Q]
                return {
                    "name": "VLAN",
                    "fields": {
                        "vlan": vlan.vlan,
                        "prio": vlan.prio,
                        "type": hex(vlan.type),
                    },
                    "summary": f"VLAN(vlan={vlan.vlan})",
                }
            
            # ARP
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                return {
                    "name": "ARP",
                    "fields": {
                        "op": arp.op,
                        "hwsrc": arp.hwsrc,
                        "psrc": arp.psrc,
                        "hwdst": arp.hwdst,
                        "pdst": arp.pdst,
                    },
                    "summary": f"ARP(op={arp.op}, {arp.psrc} -> {arp.pdst})",
                }
            
            # IPv4
            if pkt.haslayer(IP):
                ip = pkt[IP]
                return {
                    "name": "IPv4",
                    "fields": {
                        "version": ip.version,
                        "src": ip.src,
                        "dst": ip.dst,
                        "proto": ip.proto,
                        "len": ip.len,
                        "ttl": ip.ttl,
                    },
                    "summary": f"IP({ip.src} -> {ip.dst})",
                }
            
            # IPv6
            if pkt.haslayer(IPv6):
                ipv6 = pkt[IPv6]
                return {
                    "name": "IPv6",
                    "fields": {
                        "version": ipv6.version,
                        "src": ipv6.src,
                        "dst": ipv6.dst,
                        "nh": ipv6.nh,
                        "plen": ipv6.plen,
                        "hlim": ipv6.hlim,
                    },
                    "summary": f"IPv6({ipv6.src} -> {ipv6.dst})",
                }
            
            # ICMP
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                return {
                    "name": "ICMP",
                    "fields": {
                        "type": icmp.type,
                        "code": icmp.code,
                    },
                    "summary": f"ICMP(type={icmp.type}, code={icmp.code})",
                }
            
            # ICMPv6
            if pkt.haslayer(ICMPv6ND_NS):
                icmp6 = pkt[ICMPv6ND_NS]
                return {
                    "name": "ICMPv6",
                    "fields": {
                        "type": icmp6.type,
                    },
                    "summary": "ICMPv6 ND",
                }
            
            # TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                if tcp.flags.P: flags.append("PSH")
                if tcp.flags.U: flags.append("URG")
                
                return {
                    "name": "TCP",
                    "fields": {
                        "sport": tcp.sport,
                        "dport": tcp.dport,
                        "seq": tcp.seq,
                        "ack": tcp.ack,
                        "flags": "".join(flags),
                        "window": tcp.window,
                    },
                    "summary": f"TCP({tcp.sport} -> {tcp.dport}) {' '.join(flags)}",
                }
            
            # UDP
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                return {
                    "name": "UDP",
                    "fields": {
                        "sport": udp.sport,
                        "dport": udp.dport,
                        "len": udp.len,
                    },
                    "summary": f"UDP({udp.sport} -> {udp.dport})",
                }
            
            # Generic fallback
            layer_name = pkt.__class__.__name__
            return {
                "name": layer_name,
                "fields": {"_raw": str(pkt)[:200]},
                "summary": layer_name,
            }
            
        except Exception as e:
            logger.debug(f"Error decoding layer: {e}")
            return None
    
    def get_supported_protocols(self) -> List[str]:
        """Return list of supported protocols."""
        return self._supported_protocols.copy()


class LayerDecoder:
    """Base class for protocol layer decoders."""
    
    def decode(self, pkt: Packet) -> Optional[DecodedProtocol]:
        raise NotImplementedError
    
    def matches(self, pkt: Packet) -> bool:
        raise NotImplementedError
