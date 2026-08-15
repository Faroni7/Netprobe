"""
HTTP Decoder.

Decodes HTTP requests and responses from packets.
Extracts methods, URIs, headers, cookies, and authentication info.
"""

import logging
import re
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field

try:
    from scapy.all import Packet, TCP, Raw, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from netsec_platform.models.core_models import (
    ArtifactType,
    SensitiveArtifact,
    DetectionConfidence,
    EncryptionState,
)


logger = logging.getLogger(__name__)


@dataclass
class HTTPRequest:
    """Parsed HTTP request."""
    method: str
    uri: str
    version: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    
    # Parsed components
    host: Optional[str] = None
    path: Optional[str] = None
    query_params: Optional[str] = None
    
    # Auth artifacts
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    auth_type: Optional[str] = None
    auth_value: Optional[str] = None


@dataclass
class HTTPResponse:
    """Parsed HTTP response."""
    version: str
    status_code: int
    status_text: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    
    # Parsed components
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    
    # Security headers
    security_headers: Dict[str, Optional[str]] = field(default_factory=dict)


class HTTPDecoder:
    """
    HTTP protocol decoder.
    
    Extracts HTTP metadata from packets including:
    - Request/response parsing
    - Header extraction
    - Cookie analysis
    - Authentication detection
    - Sensitive data detection
    """
    
    def __init__(self):
        self._request_buffer: Dict[str, bytes] = {}  # flow_key -> buffered data
        logger.info("HTTPDecoder initialized")
    
    def decode_http_packet(
        self,
        pkt: Packet,
        timestamp: datetime,
    ) -> Tuple[Optional[HTTPRequest], Optional[HTTPResponse]]:
        """Decode HTTP from a packet."""
        if not SCAPY_AVAILABLE or not pkt.haslayer(TCP):
            return None, None
        
        try:
            tcp = pkt[TCP]
            
            # Check for raw payload
            if not pkt.haslayer(Raw):
                return None, None
            
            raw_data = bytes(pkt[Raw].load)
            
            # Try to decode as HTTP
            try:
                http_text = raw_data.decode('utf-8', errors='ignore')
            except Exception:
                return None, None
            
            # Check if request or response
            if http_text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                request = self._parse_request(http_text, raw_data, pkt, timestamp)
                return request, None
            elif http_text.startswith('HTTP/'):
                response = self._parse_response(http_text, raw_data, pkt, timestamp)
                return None, response
            
            return None, None
            
        except Exception as e:
            logger.debug(f"HTTP decode error: {e}")
            return None, None
    
    def _parse_request(
        self,
        http_text: str,
        raw_data: bytes,
        pkt: Packet,
        timestamp: datetime,
    ) -> Optional[HTTPRequest]:
        """Parse HTTP request."""
        try:
            lines = http_text.split('\r\n')
            if not lines:
                return None
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
            
            method = parts[0]
            uri = parts[1]
            version = parts[2]
            
            # Parse headers
            headers: Dict[str, str] = {}
            body_start = 1
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Get body
            body = None
            if body_start < len(lines):
                body = '\r\n'.join(lines[body_start:]).encode()
            
            # Parse URI components
            path = uri
            query_params = None
            if '?' in uri:
                path, query_params = uri.split('?', 1)
            
            # Parse cookies
            cookies = []
            cookie_header = headers.get('Cookie', '')
            if cookie_header:
                cookies = self._parse_cookies(cookie_header)
            
            # Parse auth
            auth_type = None
            auth_value = None
            auth_header = headers.get('Authorization', '')
            if auth_header:
                if auth_header.startswith('Basic '):
                    auth_type = 'BASIC'
                    auth_value = auth_header[6:]
                elif auth_header.startswith('Bearer '):
                    auth_type = 'BEARER'
                    auth_value = auth_header[7:]
            
            return HTTPRequest(
                method=method,
                uri=uri,
                version=version,
                headers=headers,
                body=body,
                host=headers.get('Host'),
                path=path,
                query_params=query_params,
                cookies=cookies,
                auth_type=auth_type,
                auth_value=auth_value,
            )
            
        except Exception as e:
            logger.debug(f"Request parse error: {e}")
            return None
    
    def _parse_response(
        self,
        http_text: str,
        raw_data: bytes,
        pkt: Packet,
        timestamp: datetime,
    ) -> Optional[HTTPResponse]:
        """Parse HTTP response."""
        try:
            lines = http_text.split('\r\n')
            if not lines:
                return None
            
            # Parse status line
            status_line = lines[0]
            parts = status_line.split(' ', 2)
            if len(parts) < 3:
                return None
            
            version = parts[0]
            status_code = int(parts[1])
            status_text = parts[2]
            
            # Parse headers
            headers: Dict[str, str] = {}
            body_start = 1
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Get body
            body = None
            if body_start < len(lines):
                body = '\r\n'.join(lines[body_start:]).encode()
            
            # Parse Set-Cookie headers
            cookies = []
            for header_name, header_value in headers.items():
                if header_name.lower() == 'set-cookie':
                    cookies.extend(self._parse_set_cookie(header_value))
            
            # Security headers
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy'),
            }
            
            return HTTPResponse(
                version=version,
                status_code=status_code,
                status_text=status_text,
                headers=headers,
                body=body,
                content_type=headers.get('Content-Type'),
                content_length=int(headers['Content-Length']) if 'Content-Length' in headers else None,
                cookies=cookies,
                security_headers=security_headers,
            )
            
        except Exception as e:
            logger.debug(f"Response parse error: {e}")
            return None
    
    def _parse_cookies(self, cookie_header: str) -> List[Dict[str, Any]]:
        """Parse Cookie header."""
        cookies = []
        for part in cookie_header.split(';'):
            part = part.strip()
            if '=' in part:
                name, value = part.split('=', 1)
                cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                })
        return cookies
    
    def _parse_set_cookie(self, set_cookie_header: str) -> List[Dict[str, Any]]:
        """Parse Set-Cookie header."""
        cookies = []
        parts = set_cookie_header.split(';')
        
        if parts and '=' in parts[0]:
            name, value = parts[0].split('=', 1)
            cookie = {
                "name": name.strip(),
                "value": value.strip(),
            }
            
            # Parse attributes
            for part in parts[1:]:
                part = part.strip()
                if '=' in part:
                    attr_name, attr_value = part.split('=', 1)
                    cookie[attr_name.strip().lower()] = attr_value.strip()
                else:
                    cookie[part.strip().lower()] = True
            
            cookies.append(cookie)
        
        return cookies
    
    def detect_sensitive_artifacts(
        self,
        request: Optional[HTTPRequest],
        response: Optional[HTTPResponse],
        src_ip: Optional[str],
        dst_ip: Optional[str],
        timestamp: datetime,
        flow_id: Optional[str],
        packet_id: Optional[int],
    ) -> List[SensitiveArtifact]:
        """Detect sensitive artifacts in HTTP traffic."""
        artifacts = []
        
        if request:
            # Check for credentials in request
            if request.auth_type == 'BASIC' and request.auth_value:
                artifacts.append(SensitiveArtifact(
                    artifact_id=f"eid-basic-{packet_id}",
                    artifact_type=ArtifactType.BASIC_AUTH,
                    field_name="Authorization",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="HTTP",
                    app_protocol="HTTP",
                    http_method=request.method,
                    url_path=request.path,
                    timestamp=timestamp,
                    flow_id=flow_id,
                    packet_id=packet_id,
                    transport_encryption=EncryptionState.PLAINTEXT,
                    confidence=DetectionConfidence.HIGH,
                ))
            
            if request.auth_type == 'BEARER' and request.auth_value:
                artifacts.append(SensitiveArtifact(
                    artifact_id=f"eid-bearer-{packet_id}",
                    artifact_type=ArtifactType.BEARER_TOKEN,
                    field_name="Authorization",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="HTTP",
                    app_protocol="HTTP",
                    http_method=request.method,
                    url_path=request.path,
                    timestamp=timestamp,
                    flow_id=flow_id,
                    packet_id=packet_id,
                    transport_encryption=EncryptionState.PLAINTEXT,
                    confidence=DetectionConfidence.HIGH,
                ))
            
            # Check cookies for session indicators
            for cookie in request.cookies:
                cookie_lower = cookie["name"].lower()
                if any(indicator in cookie_lower for indicator in ['session', 'sess', 'sid', 'auth']):
                    artifacts.append(SensitiveArtifact(
                        artifact_id=f"eid-cookie-{packet_id}-{cookie['name']}",
                        artifact_type=ArtifactType.SESSION_COOKIE,
                        field_name=cookie["name"],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="HTTP",
                        app_protocol="HTTP",
                        http_method=request.method,
                        url_path=request.path,
                        timestamp=timestamp,
                        flow_id=flow_id,
                        packet_id=packet_id,
                        transport_encryption=EncryptionState.PLAINTEXT,
                        confidence=DetectionConfidence.MEDIUM,
                        metadata={"cookie_name": cookie["name"]},
                    ))
        
        if response:
            # Check Set-Cookie for auth cookies
            for cookie in response.cookies:
                cookie_lower = cookie.get("name", "").lower()
                if any(indicator in cookie_lower for indicator in ['session', 'sess', 'sid', 'auth']):
                    artifacts.append(SensitiveArtifact(
                        artifact_id=f"eid-setcookie-{packet_id}-{cookie.get('name')}",
                        artifact_type=ArtifactType.AUTH_COOKIE,
                        field_name=cookie.get("name"),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol="HTTP",
                        app_protocol="HTTP",
                        timestamp=timestamp,
                        flow_id=flow_id,
                        packet_id=packet_id,
                        transport_encryption=EncryptionState.PLAINTEXT,
                        confidence=DetectionConfidence.MEDIUM,
                        metadata={
                            "cookie_name": cookie.get("name"),
                            "secure": cookie.get("secure", False),
                            "httponly": cookie.get("httponly", False),
                            "samesite": cookie.get("samesite"),
                        },
                    ))
        
        return artifacts
    
    def analyze_security_headers(
        self,
        response: HTTPResponse,
    ) -> List[Dict[str, Any]]:
        """Analyze HTTP security headers and identify missing/weak ones."""
        findings = []
        
        missing_headers = []
        for header, value in response.security_headers.items():
            if value is None:
                missing_headers.append(header)
        
        if missing_headers:
            findings.append({
                "type": "MISSING_SECURITY_HEADERS",
                "severity": "low",
                "headers": missing_headers,
            })
        
        # Check for weak configurations
        if response.security_headers.get('X-Frame-Options') is None and \
           not any('FRAME-OPTIONS' in k.upper() for k in response.headers.keys()):
            findings.append({
                "type": "CLICKJACKING_RISK",
                "severity": "medium",
                "description": "X-Frame-Options header missing",
            })
        
        return findings
