export interface NetworkFlow {
  fid: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  src_mac?: string;
  dst_mac?: string;
  transport_proto: string;
  app_proto?: string;
  start_time: string;
  end_time?: string;
  duration_ms: number;
  packets_sent: number;
  packets_received: number;
  bytes_sent: number;
  bytes_received: number;
  tcp_state?: string;
  encryption: 'PLAINTEXT' | 'ENCRYPTED' | 'DECRYPTED' | 'PARTIALLY_DECODED' | 'UNKNOWN';
  security_quality: 'GOOD' | 'WEAK' | 'INSECURE' | 'UNKNOWN';
}

export interface SensitiveArtifact {
  eid: string;
  artifact_type: string;
  field_name: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  domain?: string;
  host?: string;
  proto: string;
  app_proto?: string;
  http_method?: string;
  url_path?: string;
  timestamp: string;
  fid?: string;
  packet_id?: number;
  capture_id?: string;
  confidence: number;
  transport_security: string;
  evidence_hash: string;
}

export interface SecurityFinding {
  finding_id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'NEW' | 'INVESTIGATING' | 'CONFIRMED' | 'REMEDIATED' | 'FALSE_POSITIVE';
  description: string;
  affected_asset?: string;
  src_ip?: string;
  dst_ip?: string;
  proto?: string;
  timestamp: string;
  evidence_ids: string[];
  packet_references?: number[];
  explanation: string;
  remediation: string;
  related_findings?: string[];
  case_id?: string;
}

export interface Asset {
  ip_addresses: string[];
  mac_addresses: string[];
  hostnames: string[];
  dns_names: string[];
  services: ServiceInfo[];
  first_seen: string;
  last_seen: string;
  findings_count: number;
}

export interface ServiceInfo {
  port: number;
  proto: string;
  service_name?: string;
}

export interface DNSRecord {
  query: string;
  query_type: string;
  response_code: string;
  answers: string[];
  dns_server: string;
  src_ip: string;
  dst_ip: string;
  timestamp: string;
}

export interface TLSInfo {
  version: string;
  sni?: string;
  cipher_suite: string;
  cert_subject?: string;
  cert_issuer?: string;
  valid_from?: string;
  valid_until?: string;
  security_quality: 'GOOD' | 'WEAK' | 'INSECURE' | 'UNKNOWN';
}

export interface HTTPRequest {
  method: string;
  host: string;
  uri: string;
  status_code?: number;
  user_agent?: string;
  content_type?: string;
  cookies?: CookieInfo[];
  auth_type?: string;
}

export interface CookieInfo {
  name: string;
  value?: string; // Hidden by default
  domain?: string;
  path?: string;
  secure: boolean;
  http_only: boolean;
  same_site?: 'Strict' | 'Lax' | 'None';
  expires?: string;
}

export interface InvestigationCase {
  case_id: string;
  title: string;
  description: string;
  analyst: string;
  time_range_start: string;
  time_range_end: string;
  asset_ips: string[];
  indicators: string[];
  finding_ids: string[];
  evidence_ids: string[];
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: 'DISCOVERY' | 'DNS' | 'TLS' | 'HTTP' | 'AUTH' | 'FINDING' | 'EMERGENCY_STOP';
  description: string;
  severity?: string;
  finding_id?: string;
  flow_id?: string;
  evidence_id?: string;
}

export interface CaptureStatus {
  status: 'ACTIVE' | 'STOPPED' | 'PAUSED' | 'ERROR';
  interface: string;
  profile: 'METADATA_ONLY' | 'STANDARD' | 'FULL_EVIDENCE';
  packets_captured: number;
  packets_dropped: number;
  drop_rate: number;
  bytes_captured: number;
  capture_rate: number;
  processing_rate: number;
  analysis_backlog: number;
  storage_usage_bytes: number;
  started_at?: string;
}

export interface ESSStatus {
  state: 'READY' | 'ACTIVATING' | 'STOPPED' | 'RECOVERING';
  enabled: boolean;
  activated_at?: string;
  activated_by?: string;
  reason?: string;
}

export interface DashboardStats {
  total_flows: number;
  total_hosts: number;
  total_findings: number;
  critical_findings: number;
  sensitive_artifacts: number;
  plaintext_connections: number;
  encrypted_connections: number;
  dns_queries_24h: number;
  top_talkers: Array<{ ip: string; packets: number }>;
  top_destinations: Array<{ ip: string; connections: number }>;
  top_domains: Array<{ domain: string; queries: number }>;
  traffic_over_time: Array<{ timestamp: string; packets: number }>;
}

export interface User {
  id: string;
  username: string;
  role: 'ADMIN' | 'ANALYST' | 'VIEWER';
  permissions: string[];
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  expires_in: number;
}
