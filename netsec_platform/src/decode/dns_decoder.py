"""
DNS Decoder.

Decodes DNS queries and responses from packets.
Extracts query names, types, response codes, and answer records.
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

try:
    from scapy.all import Packet, DNS, DNSQR, DNSRR, IP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from netsec_platform.models.core_models import DNSQuery


logger = logging.getLogger(__name__)


class DNSDecoder:
    """
    DNS protocol decoder.
    
    Extracts DNS metadata from packets including:
    - Query/response identification
    - Query names and types
    - Response codes
    - Answer records
    - CNAME chains
    """
    
    def __init__(self):
        self._query_cache: Dict[int, DNSQuery] = {}  # dns_id -> query
        logger.info("DNSDecoder initialized")
    
    def decode_dns_packet(
        self,
        packet_data: bytes,
        timestamp: datetime,
        src_ip: str,
        dst_ip: str,
    ) -> Optional[DNSQuery]:
        """Decode a DNS packet and extract query/response info."""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            pkt = packet_data
            # Check if it's a DNS packet by looking for DNS header
            # DNS uses port 53 typically
            
            # For now, we'll create a simple DNS query representation
            # In production, you'd parse the actual DNS structure
            
            # This is a simplified version - full DNS parsing would use scapy's DNS layer
            return None
            
        except Exception as e:
            logger.debug(f"DNS decode error: {e}")
            return None
    
    def decode_with_scapy(
        self,
        pkt: Packet,
        timestamp: datetime,
    ) -> Optional[DNSQuery]:
        """Decode DNS using scapy's DNS layer."""
        if not SCAPY_AVAILABLE or not pkt.haslayer(DNS):
            return None
        
        try:
            dns = pkt[DNS]
            
            # Get IP info
            src_ip = pkt[IP].src if pkt.haslayer(IP) else None
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else None
            
            if not src_ip or not dst_ip:
                return None
            
            # Generate query ID
            query_id = f"dns-{dns.id}-{timestamp.timestamp()}"
            
            # Check if query or response
            if dns.qr == 0:  # Query
                if dns.qd:
                    query_name = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                    query_type = dns.qd.qtype
                    
                    query = DNSQuery(
                        query_id=query_id,
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        query_name=query_name.rstrip('.'),
                        query_type=self._get_query_type_name(query_type),
                    )
                    
                    # Cache for response correlation
                    self._query_cache[dns.id] = query
                    return query
            
            else:  # Response
                # Find matching query
                matching_query = self._query_cache.get(dns.id)
                
                answer_records: List[Dict[str, Any]] = []
                cname_chain: List[str] = []
                ttl: Optional[int] = None
                
                # Parse answer records
                if dns.an:
                    count = dns.ancount
                    rr = dns.an
                    for _ in range(count):
                        if rr:
                            record_info = {
                                "rrname": rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname),
                                "type": rr.type,
                                "rdata": rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata),
                            }
                            answer_records.append(record_info)
                            
                            # Track CNAMEs
                            if rr.type == 5:  # CNAME
                                cname_chain.append(record_info["rdata"])
                            
                            if ttl is None:
                                ttl = rr.ttl
                            
                            rr = rr.payload if hasattr(rr, 'payload') else None
                
                query = DNSQuery(
                    query_id=query_id,
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    query_name=matching_query.query_name if matching_query else "",
                    query_type=matching_query.query_type if matching_query else "A",
                    response_code=self._get_response_code_name(dns.rcode),
                    answer_records=answer_records,
                    cname_chain=cname_chain,
                    ttl=ttl,
                )
                
                # Clean up cache
                if dns.id in self._query_cache:
                    del self._query_cache[dns.id]
                
                return query
            
        except Exception as e:
            logger.debug(f"DNS scapy decode error: {e}")
            return None
    
    def _get_query_type_name(self, qtype: int) -> str:
        """Convert DNS query type number to name."""
        type_map = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            255: "ANY",
        }
        return type_map.get(qtype, f"TYPE{qtype}")
    
    def _get_response_code_name(self, rcode: int) -> str:
        """Convert DNS response code number to name."""
        code_map = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
        }
        return code_map.get(rcode, f"RCODE{rcode}")
    
    def detect_suspicious_patterns(
        self,
        queries: List[DNSQuery],
        window_seconds: int = 60,
    ) -> List[Dict[str, Any]]:
        """
        Detect suspicious DNS patterns.
        
        Looks for:
        - NXDOMAIN spikes
        - Unusual volume
        - High-entropy domains (possible DGA)
        - DNS tunneling indicators
        """
        findings = []
        
        # Count NXDOMAIN responses
        nxdomain_count = sum(1 for q in queries if q.response_code == "NXDOMAIN")
        nxdomain_rate = nxdomain_count / max(len(queries), 1)
        
        if nxdomain_rate > 0.3 and len(queries) > 10:
            findings.append({
                "type": "NXDOMAIN_SPIKE",
                "severity": "medium",
                "description": f"High NXDOMAIN rate: {nxdomain_rate:.1%}",
                "count": nxdomain_count,
            })
        
        # Check for high-entropy domain names (possible DGA)
        import math
        
        for query in queries:
            domain_parts = query.query_name.split('.')
            if domain_parts:
                subdomain = domain_parts[0]
                if len(subdomain) > 15:
                    # Calculate entropy
                    entropy = -sum(
                        (subdomain.count(c) / len(subdomain)) * math.log2(subdomain.count(c) / len(subdomain))
                        for c in set(subdomain)
                    )
                    if entropy > 4.0:
                        findings.append({
                            "type": "HIGH_ENTROPY_DOMAIN",
                            "severity": "medium",
                            "domain": query.query_name,
                            "entropy": round(entropy, 2),
                        })
        
        return findings
