"""
NetSec Platform - Database Layer

SQLite-based storage for flows, findings, evidence, and audit logs.
Provides schema management, migrations, and efficient querying.
"""

import sqlite3
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from ..models.core_models import (
    NetworkFlow, SecurityFinding, SensitiveArtifact,
    Asset, TLSConnection, HTTPTransaction
)


class DatabaseManager:
    """
    SQLite database manager for NetSec Platform.
    
    Features:
    - Automatic schema creation
    - Connection pooling
    - Transaction support
    - Efficient indexing
    """
    
    def __init__(self, db_path: str = "/var/netsec_platform/data/netsec.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._local = threading.local()
        self._lock = threading.Lock()
        
        self._init_schema()
    
    @contextmanager
    def get_connection(self):
        """Get a database connection from the pool."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
            # Enable foreign keys
            self._local.conn.execute("PRAGMA foreign_keys = ON")
            # Enable WAL mode for better concurrency
            self._local.conn.execute("PRAGMA journal_mode = WAL")
        
        conn = self._local.conn
        try:
            yield conn
        finally:
            pass  # Keep connection for reuse
    
    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        with self.get_connection() as conn:
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    
    def _init_schema(self):
        """Initialize database schema with all tables and indexes."""
        
        with self.transaction() as conn:
            cursor = conn.cursor()
            
            # Assets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    dns_names TEXT,  -- JSON array
                    services TEXT,   -- JSON array
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    asset_type TEXT,
                    os_fingerprint TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, mac_address)
                )
            """)
            
            # Network flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT NOT NULL UNIQUE,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    src_mac TEXT,
                    dst_mac TEXT,
                    protocol TEXT NOT NULL,
                    app_protocol TEXT,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    duration_ms INTEGER,
                    packets_sent INTEGER DEFAULT 0,
                    packets_received INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    tcp_state TEXT,
                    retransmissions INTEGER DEFAULT 0,
                    rtt_ms REAL,
                    encryption TEXT,  -- PLAINTEXT, ENCRYPTED, etc.
                    security_quality TEXT,  -- GOOD, WEAK, INSECURE
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # DNS records table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_id TEXT NOT NULL UNIQUE,
                    query_name TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    response_code TEXT,
                    answers TEXT,  -- JSON array
                    ttl INTEGER,
                    dns_server TEXT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    flow_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # TLS handshakes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_handshakes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    handshake_id TEXT NOT NULL UNIQUE,
                    tls_version TEXT,
                    sni TEXT,
                    alpn TEXT,
                    cipher_suite TEXT,
                    cert_subject TEXT,
                    cert_issuer TEXT,
                    cert_san TEXT,  -- JSON array
                    valid_from TIMESTAMP,
                    valid_until TIMESTAMP,
                    tls_fingerprint TEXT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    flow_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # HTTP requests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL UNIQUE,
                    method TEXT NOT NULL,
                    host TEXT,
                    uri TEXT,
                    query_params TEXT,  -- JSON object
                    status_code INTEGER,
                    request_headers TEXT,  -- JSON object
                    response_headers TEXT,  -- JSON object
                    user_agent TEXT,
                    content_type TEXT,
                    cookies TEXT,  -- JSON array
                    auth_method TEXT,
                    request_size INTEGER,
                    response_size INTEGER,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    flow_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Security findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
                    confidence TEXT NOT NULL,  -- HIGH, MEDIUM, LOW
                    status TEXT DEFAULT 'NEW',  -- NEW, INVESTIGATING, CONFIRMED, REMEDIATED
                    description TEXT,
                    affected_asset TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    evidence_ids TEXT,  -- JSON array
                    packet_refs TEXT,   -- JSON array
                    explanation TEXT,
                    remediation TEXT,
                    related_findings TEXT,  -- JSON array
                    case_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Sensitive artifacts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sensitive_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id TEXT NOT NULL UNIQUE,
                    artifact_type TEXT NOT NULL,
                    field_name TEXT,
                    encrypted_value BLOB,  -- Encrypted sensitive value
                    value_hash TEXT,  -- SHA-256 hash for identification
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    domain TEXT,
                    host TEXT,
                    protocol TEXT,
                    app_protocol TEXT,
                    http_method TEXT,
                    url_path TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    flow_id TEXT,
                    packet_id INTEGER,
                    capture_id TEXT,
                    detection_confidence REAL,
                    transport_security TEXT,
                    evidence_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Evidence store table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT NOT NULL UNIQUE,
                    evidence_type TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    file_path TEXT,
                    file_hash TEXT,  -- SHA-256 of file
                    file_size INTEGER,
                    mime_type TEXT,
                    metadata TEXT,  -- JSON object
                    case_id TEXT,
                    chain_of_custody TEXT,  -- JSON array
                    integrity_verified BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """)
            
            # Investigation cases table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    description TEXT,
                    analyst TEXT,
                    status TEXT DEFAULT 'OPEN',  -- OPEN, CLOSED, ARCHIVED
                    time_range_start TIMESTAMP,
                    time_range_end TIMESTAMP,
                    assets TEXT,  -- JSON array
                    connections TEXT,  -- JSON array
                    domains TEXT,  -- JSON array
                    indicators TEXT,  -- JSON array (IOCs)
                    findings TEXT,  -- JSON array
                    evidence TEXT,  -- JSON array
                    notes TEXT,
                    timeline TEXT,  -- JSON array
                    exports TEXT,  -- JSON array
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP,
                    closed_at TIMESTAMP
                )
            """)
            
            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    details TEXT,  -- JSON object (no sensitive data)
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    success BOOLEAN DEFAULT TRUE,
                    error_message TEXT
                )
            """)
            
            # Capture sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS capture_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL UNIQUE,
                    interface TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    status TEXT DEFAULT 'STOPPED',  -- RUNNING, STOPPED, PAUSED
                    filter_expression TEXT,
                    snap_length INTEGER,
                    max_packets INTEGER,
                    max_size_mb INTEGER,
                    max_duration_sec INTEGER,
                    packets_captured INTEGER DEFAULT 0,
                    packets_dropped INTEGER DEFAULT 0,
                    bytes_captured INTEGER DEFAULT 0,
                    started_at TIMESTAMP,
                    stopped_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Controlled tests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS controlled_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_id TEXT NOT NULL UNIQUE,
                    test_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    target_ip TEXT,
                    artifact_id TEXT,
                    authz_reference TEXT,
                    scope TEXT,  -- JSON array
                    status TEXT DEFAULT 'PENDING',  -- PENDING, RUNNING, COMPLETED, FAILED, ABORTED
                    rate_limit INTEGER,
                    max_requests INTEGER,
                    timeout_sec INTEGER,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    request_count INTEGER DEFAULT 0,
                    result TEXT,  -- JSON object
                    errors TEXT,  -- JSON array
                    evidence_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Emergency stop events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS emergency_stop_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    operator TEXT NOT NULL,
                    reason TEXT,
                    capture_status TEXT,
                    processing_status TEXT,
                    test_status TEXT,
                    evidence_status TEXT,
                    exports_status TEXT,
                    sensitive_evidence_locked BOOLEAN DEFAULT TRUE,
                    timestamp TIMESTAMP NOT NULL,
                    recovery_operator TEXT,
                    recovery_timestamp TIMESTAMP,
                    recovery_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for efficient querying
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip)",
                "CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip)",
                "CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol)",
                "CREATE INDEX IF NOT EXISTS idx_flows_start_time ON flows(start_time)",
                "CREATE INDEX IF NOT EXISTS idx_flows_encryption ON flows(encryption)",
                
                "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
                "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)",
                "CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id)",
                
                "CREATE INDEX IF NOT EXISTS idx_dns_query_name ON dns_records(query_name)",
                "CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_records(timestamp)",
                
                "CREATE INDEX IF NOT EXISTS idx_tls_sni ON tls_handshakes(sni)",
                "CREATE INDEX IF NOT EXISTS idx_tls_timestamp ON tls_handshakes(timestamp)",
                
                "CREATE INDEX IF NOT EXISTS idx_http_host ON http_requests(host)",
                "CREATE INDEX IF NOT EXISTS idx_http_timestamp ON http_requests(timestamp)",
                
                "CREATE INDEX IF NOT EXISTS idx_artifacts_type ON sensitive_artifacts(artifact_type)",
                "CREATE INDEX IF NOT EXISTS idx_artifacts_src_ip ON sensitive_artifacts(src_ip)",
                "CREATE INDEX IF NOT EXISTS idx_artifacts_dst_ip ON sensitive_artifacts(dst_ip)",
                
                "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)",
                
                "CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address)",
                "CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname)",
                
                "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)",
                "CREATE INDEX IF NOT EXISTS idx_cases_analyst ON cases(analyst)",
            ]
            
            for index_sql in indexes:
                cursor.execute(index_sql)
    
    # Flow operations
    def insert_flow(self, flow: NetworkFlow) -> int:
        """Insert a network flow into the database."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO flows (
                    flow_id, src_ip, src_port, dst_ip, dst_port,
                    src_mac, dst_mac, protocol, app_protocol,
                    start_time, end_time, duration_ms,
                    packets_sent, packets_received, bytes_sent, bytes_received,
                    tcp_state, retransmissions, rtt_ms,
                    encryption, security_quality,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow.flow_id, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                flow.src_mac, flow.dst_mac, flow.protocol, flow.app_protocol,
                flow.start_time, flow.end_time, flow.duration_ms,
                flow.packets_sent, flow.packets_received, flow.bytes_sent, flow.bytes_received,
                flow.tcp_state, flow.retransmissions, flow.rtt_ms,
                flow.encryption, flow.security_quality,
                flow.first_seen, flow.last_seen
            ))
            return cursor.lastrowid
    
    def get_flows(self, limit: int = 100, offset: int = 0,
                  filters: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """Query flows with optional filters."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM flows WHERE 1=1"
            params = []
            
            if filters:
                if 'src_ip' in filters:
                    query += " AND src_ip = ?"
                    params.append(filters['src_ip'])
                if 'dst_ip' in filters:
                    query += " AND dst_ip = ?"
                    params.append(filters['dst_ip'])
                if 'protocol' in filters:
                    query += " AND protocol = ?"
                    params.append(filters['protocol'])
                if 'encryption' in filters:
                    query += " AND encryption = ?"
                    params.append(filters['encryption'])
                if 'start_time_gte' in filters:
                    query += " AND start_time >= ?"
                    params.append(filters['start_time_gte'])
            
            query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    # Finding operations
    def insert_finding(self, finding: SecurityFinding) -> int:
        """Insert a security finding into the database."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO findings (
                    finding_id, title, severity, confidence, status,
                    description, affected_asset, src_ip, dst_ip, protocol,
                    timestamp, evidence_ids, packet_refs, explanation,
                    remediation, related_findings, case_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.finding_id, finding.title, finding.severity,
                finding.confidence, finding.status, finding.description,
                finding.affected_asset, finding.src_ip, finding.dst_ip,
                finding.protocol, finding.timestamp,
                json.dumps(finding.evidence_ids),
                json.dumps(finding.packet_refs),
                finding.explanation, finding.remediation,
                json.dumps(finding.related_findings), finding.case_id
            ))
            return cursor.lastrowid
    
    def get_findings(self, limit: int = 100, offset: int = 0,
                     filters: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """Query findings with optional filters."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            
            if filters:
                if 'severity' in filters:
                    query += " AND severity = ?"
                    params.append(filters['severity'])
                if 'status' in filters:
                    query += " AND status = ?"
                    params.append(filters['status'])
                if 'case_id' in filters:
                    query += " AND case_id = ?"
                    params.append(filters['case_id'])
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    # DNS operations
    def insert_dns_record(self, record_data: Dict[str, Any]) -> int:
        """Insert a DNS record into the database."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO dns_records (
                    query_id, query_name, query_type, response_code,
                    answers, ttl, dns_server, src_ip, dst_ip,
                    timestamp, flow_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.query_id, record.query_name, record.query_type,
                record.response_code, json.dumps(record.answers),
                record.ttl, record.dns_server, record.src_ip,
                record.dst_ip, record.timestamp, record.flow_id
            ))
            return cursor.lastrowid
    
    # TLS operations
    def insert_tls_handshake(self, handshake_data: Dict[str, Any]) -> int:
        """Insert a TLS handshake into the database."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tls_handshakes (
                    handshake_id, tls_version, sni, alpn, cipher_suite,
                    cert_subject, cert_issuer, cert_san, valid_from,
                    valid_until, tls_fingerprint, src_ip, dst_ip,
                    timestamp, flow_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                handshake.handshake_id, handshake.tls_version, handshake.sni,
                handshake.alpn, handshake.cipher_suite, handshake.cert_subject,
                handshake.cert_issuer, json.dumps(handshake.cert_san),
                handshake.valid_from, handshake.valid_until,
                handshake.tls_fingerprint, handshake.src_ip,
                handshake.dst_ip, handshake.timestamp, handshake.flow_id
            ))
            return cursor.lastrowid
    
    # HTTP operations
    def insert_http_request(self, request_data: Dict[str, Any]) -> int:
        """Insert an HTTP request into the database."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO http_requests (
                    request_id, method, host, uri, query_params,
                    status_code, request_headers, response_headers,
                    user_agent, content_type, cookies, auth_method,
                    request_size, response_size, src_ip, dst_ip,
                    timestamp, flow_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.request_id, request.method, request.host, request.uri,
                json.dumps(request.query_params) if request.query_params else None,
                request.status_code, json.dumps(request.request_headers),
                json.dumps(request.response_headers), request.user_agent,
                request.content_type, json.dumps(request.cookies),
                request.auth_method, request.request_size, request.response_size,
                request.src_ip, request.dst_ip, request.timestamp, request.flow_id
            ))
            return cursor.lastrowid
    
    # Asset operations
    def insert_or_update_asset(self, asset: Asset) -> int:
        """Insert or update an asset in the database."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO assets (
                    ip_address, mac_address, hostname, dns_names, services,
                    first_seen, last_seen, asset_type, os_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address, mac_address) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    hostname = COALESCE(excluded.hostname, assets.hostname),
                    dns_names = COALESCE(excluded.dns_names, assets.dns_names),
                    services = COALESCE(excluded.services, assets.services),
                    asset_type = COALESCE(excluded.asset_type, assets.asset_type),
                    os_fingerprint = COALESCE(excluded.os_fingerprint, assets.os_fingerprint)
            """, (
                asset.ip_address, asset.mac_address, asset.hostname,
                json.dumps(asset.dns_names), json.dumps(asset.services),
                asset.first_seen, asset.last_seen, asset.asset_type,
                asset.os_fingerprint
            ))
            return cursor.lastrowid
    
    # Case operations
    def create_case(self, case_data: Dict[str, Any]) -> int:
        """Create a new investigation case."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cases (
                    case_id, title, description, analyst, status,
                    time_range_start, time_range_end, assets, connections,
                    domains, indicators, findings, evidence, notes, timeline, exports
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_data['case_id'], case_data['title'],
                case_data.get('description'), case_data.get('analyst'),
                case_data.get('status', 'OPEN'),
                case_data.get('time_range_start'), case_data.get('time_range_end'),
                json.dumps(case_data.get('assets', [])),
                json.dumps(case_data.get('connections', [])),
                json.dumps(case_data.get('domains', [])),
                json.dumps(case_data.get('indicators', [])),
                json.dumps(case_data.get('findings', [])),
                json.dumps(case_data.get('evidence', [])),
                case_data.get('notes'),
                json.dumps(case_data.get('timeline', [])),
                json.dumps(case_data.get('exports', []))
            ))
            return cursor.lastrowid
    
    def get_case(self, case_id: str) -> Optional[Dict]:
        """Retrieve a case by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # Statistics operations
    def get_statistics(self) -> Dict[str, Any]:
        """Get platform statistics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total counts
            cursor.execute("SELECT COUNT(*) FROM flows")
            stats['total_flows'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM findings")
            stats['total_findings'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sensitive_artifacts")
            stats['total_artifacts'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM assets")
            stats['total_assets'] = cursor.fetchone()[0]
            
            # Findings by severity
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM findings 
                GROUP BY severity
            """)
            stats['findings_by_severity'] = {
                row['severity']: row[1] for row in cursor.fetchall()
            }
            
            # Top talkers
            cursor.execute("""
                SELECT src_ip, COUNT(*) as flow_count, SUM(bytes_sent) as total_bytes
                FROM flows
                GROUP BY src_ip
                ORDER BY flow_count DESC
                LIMIT 10
            """)
            stats['top_talkers'] = [dict(row) for row in cursor.fetchall()]
            
            # Top destinations
            cursor.execute("""
                SELECT dst_ip, COUNT(*) as flow_count
                FROM flows
                GROUP BY dst_ip
                ORDER BY flow_count DESC
                LIMIT 10
            """)
            stats['top_destinations'] = [dict(row) for row in cursor.fetchall()]
            
            # Encryption distribution
            cursor.execute("""
                SELECT encryption, COUNT(*) as count
                FROM flows
                GROUP BY encryption
            """)
            stats['encryption_distribution'] = {
                row['encryption']: row[1] for row in cursor.fetchall()
            }
            
            return stats
    
    def close(self):
        """Close all database connections."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
