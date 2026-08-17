/**
 * TypeScript Configuration Types for NetSec Platform
 * 
 * These types mirror the backend Pydantic schema and provide
 * type safety for the configuration UI.
 */

// ============================================================================
// Enums
// ============================================================================

export enum CaptureProfile {
  METADATA_ONLY = 'metadata_only',
  STANDARD = 'standard',
  FULL_EVIDENCE = 'full_evidence'
}

export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

export enum EnvironmentType {
  DEVELOPMENT = 'development',
  TESTING = 'testing',
  PRODUCTION = 'production'
}

export enum HashAlgorithm {
  SHA256 = 'sha256',
  SHA384 = 'sha384',
  SHA512 = 'sha512'
}

// ============================================================================
// Configuration Sections
// ============================================================================

export interface AppConfig {
  environment: EnvironmentType;
  host: string;
  port: number;
  log_level: LogLevel;
  debug_mode: boolean;
  timezone: string;
}

export interface NetworkConfig {
  allowed_origins: string[];
  trusted_proxies: string[];
  request_timeout_seconds: number;
  max_request_size_mb: number;
  rate_limit_per_minute: number;
}

export interface CaptureConfig {
  enabled: boolean;
  interface: string | null;
  profile: CaptureProfile;
  filter: string | null;
  snaplen_bytes: number;
  promiscuous_mode: boolean;
  buffer_size_mb: number;
  max_storage_gb: number;
  worker_count: number;
  queue_size: number;
}

export interface EvidenceConfig {
  storage_path: string;
  encryption_enabled: boolean;
  encryption_key: string | null;
  hash_algorithm: HashAlgorithm;
  retention_days: number;
  immutable_storage: boolean;
  compression_enabled: boolean;
  backup_enabled: boolean;
}

export interface AuthConfig {
  session_timeout_minutes: number;
  idle_timeout_minutes: number;
  max_login_attempts: number;
  lockout_duration_minutes: number;
  require_mfa: boolean;
  jwt_secret: string | null;
}

export interface AuditConfig {
  enabled: boolean;
  storage_path: string;
  retention_days: number;
  include_request_body: boolean;
  remote_destination: string | null;
}

export interface TestingConfig {
  enabled: boolean;
  require_authorization: boolean;
  require_scope: boolean;
  max_rate_limit: number;
  max_duration_minutes: number;
  emergency_stop_enabled: boolean;
}

export interface ESSConfig {
  enabled: boolean;
  require_confirmation: boolean;
  auto_lock_evidence: boolean;
  recovery_requires_admin: boolean;
}

// ============================================================================
// Master Configuration Schema
// ============================================================================

export interface ConfigurationSchema {
  app: AppConfig;
  network: NetworkConfig;
  capture: CaptureConfig;
  evidence: EvidenceConfig;
  auth: AuthConfig;
  audit: AuditConfig;
  testing: TestingConfig;
  ess: ESSConfig;
}

// ============================================================================
// Metadata and UI Types
// ============================================================================

export interface ConfigMetadata {
  category: string;
  restart_required: boolean;
  runtime_reload: boolean;
  security_critical: boolean;
  locked?: boolean;
  description: string;
}

export interface ConfigValueWithMetadata<T = any> {
  value: T;
  default: T;
  source: 'DEFAULT' | 'CONFIG_FILE' | 'ENVIRONMENT' | 'RUNTIME' | 'SECRET_MANAGER';
  metadata: ConfigMetadata;
  configured?: boolean;
  redacted?: boolean;
}

export interface ConfigFieldDefinition {
  path: string;
  name: string;
  type: 'string' | 'number' | 'boolean' | 'enum' | 'array' | 'secret';
  category: string;
  description: string;
  required: boolean;
  defaultValue: any;
  allowedValues?: any[];
  minimum?: number;
  maximum?: number;
  sensitive: boolean;
  restartRequired: boolean;
  runtimeReload: boolean;
  securityCritical: boolean;
  locked: boolean;
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface ConfigUpdateRequest {
  path: string;
  value: any;
}

export interface ConfigValidateRequest {
  configuration: Partial<ConfigurationSchema>;
}

export interface ConfigSchemaResponse {
  sections: Record<string, any>;
  metadata: Record<string, ConfigMetadata>;
}

export interface ConfigStatusResponse {
  valid: boolean;
  version_hash: string;
  last_modified: string | null;
  last_modified_by: string | null;
  config_file_exists: boolean;
  environment_overrides: number;
  runtime_overrides: number;
  locked_settings: string[];
  security_warnings: string[];
}

export interface ConfigChangeDiff {
  path: string;
  before: any;
  after: any;
  restartRequired: boolean;
  securityCritical: boolean;
  description: string;
}

// ============================================================================
// Category Definitions
// ============================================================================

export const CONFIG_CATEGORIES = {
  General: ['app.environment', 'app.host', 'app.port', 'app.log_level', 'app.debug_mode', 'app.timezone'],
  Network: ['network.allowed_origins', 'network.trusted_proxies', 'network.request_timeout_seconds'],
  'Traffic Capture': ['capture.enabled', 'capture.interface', 'capture.profile', 'capture.filter'],
  'Traffic Analysis': ['analysis.enabled', 'analysis.worker_count', 'analysis.timeout'],
  Evidence: ['evidence.storage_path', 'evidence.encryption_enabled', 'evidence.retention_days'],
  Authentication: ['auth.session_timeout_minutes', 'auth.max_login_attempts', 'auth.require_mfa'],
  'Audit Logging': ['audit.enabled', 'audit.retention_days', 'audit.storage_path'],
  Storage: ['storage.data_path', 'storage.max_size', 'retention.evidence'],
  Performance: ['performance.worker_count', 'performance.queue_size', 'performance.memory_limit'],
  'Authorized Pentesting': ['testing.enabled', 'testing.require_authorization', 'testing.max_rate_limit'],
  'Emergency Security Stop': ['ess.enabled', 'ess.require_confirmation', 'ess.auto_lock_evidence'],
  Advanced: []
} as const;

export type ConfigCategory = keyof typeof CONFIG_CATEGORIES;

// ============================================================================
// Helper Functions
// ============================================================================

export function getConfigCategory(path: string): ConfigCategory {
  for (const [category, paths] of Object.entries(CONFIG_CATEGORIES)) {
    if (paths.includes(path)) {
      return category as ConfigCategory;
    }
  }
  return 'Advanced';
}

export function isSecretPath(path: string): boolean {
  const secretPaths = [
    'evidence.encryption_key',
    'auth.jwt_secret',
    'network.trusted_proxies'
  ];
  return secretPaths.includes(path);
}

export function isLockedSetting(path: string): boolean {
  const lockedPaths = [
    'testing.require_authorization',
    'testing.require_scope',
    'testing.emergency_stop_enabled',
    'ess.enabled'
  ];
  return lockedPaths.includes(path);
}
