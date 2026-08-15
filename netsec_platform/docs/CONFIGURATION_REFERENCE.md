# Configuration Reference

Complete technical reference for all NetSec Platform configuration options.

**Status:** VERIFIED  
**Total Options:** 47  
**Security Critical:** 18  
**Last Updated:** 2026

---

## Master Inventory

| Configuration Path | Type | Default | Environment Variable | Restart | Security |
|---|---|---|---|---|---|
| `app_name` | string | "NetSec Platform" | NETSEC_APP_NAME | NO | NO |
| `debug` | boolean | False | NETSEC_DEBUG | NO | NO |
| `log_level` | string | "INFO" | NETSEC_LOG_LEVEL | YES | NO |
| `api_host` | string | "127.0.0.1" | NETSEC_API_HOST | YES | YES |
| `api_port` | integer | 8000 | NETSEC_API_PORT | YES | YES |
| `api_key` | string\|null | None | NETSEC_API_KEY | YES | YES |
| `session_timeout_minutes` | integer | 60 | NETSEC_SESSION_TIMEOUT_MINUTES | YES | YES |
| `require_mfa` | boolean | False | NETSEC_REQUIRE_MFA | YES | YES |
| `storage.base_path` | string | "/var/netsec_platform/data" | NETSEC_STORAGE__BASE_PATH | YES | NO |
| `storage.evidence_path` | string | "evidence" | NETSEC_STORAGE__EVIDENCE_PATH | YES | YES |
| `storage.encrypt_evidence_at_rest` | boolean | True | NETSEC_STORAGE__ENCRYPT_EVIDENCE_AT_REST | YES | YES |
| `capture.profile` | enum | "standard" | NETSEC_CAPTURE__PROFILE | YES | YES |
| `capture.interface` | string\|null | None | NETSEC_CAPTURE__INTERFACE | YES | NO |
| `capture.ring_buffer_size_mb` | integer | 512 | NETSEC_CAPTURE__RING_BUFFER_SIZE_MB | YES | NO |
| `scope.allowed_cidrs` | list | [] | NETSEC_SCOPE__ALLOWED_CIDRS | NO | YES |
| `scope.auth_reference` | string\|null | None | NETSEC_SCOPE__AUTH_REFERENCE | NO | YES |
| `ess.enabled` | boolean | True | NETSEC_ESS__ENABLED | NO | YES |
| `ess.require_confirmation` | boolean | True | NETSEC_ESS__REQUIRE_CONFIRMATION | NO | YES |
| `ess.lock_sensitive_evidence` | boolean | True | NETSEC_ESS__LOCK_SENSITIVE_EVIDENCE | NO | YES |
| `controlled_test.enabled` | boolean | False | NETSEC_CONTROLLED_TEST__ENABLED | YES | YES |
| `controlled_test.max_requests_per_second` | integer | 10 | NETSEC_CONTROLLED_TEST__MAX_REQUESTS_PER_SECOND | NO | YES |
| `controlled_test.require_explicit_approval` | boolean | True | NETSEC_CONTROLLED_TEST__REQUIRE_EXPLICIT_APPROVAL | NO | YES |
| `controlled_test.validate_target_scope` | boolean | True | NETSEC_CONTROLLED_TEST__VALIDATE_TARGET_SCOPE | NO | YES |

*Note: Table shows key settings. Full inventory includes all 47 options.*

---

## Configuration Sources and Precedence

1. **CLI Arguments** (highest priority)
2. **Environment Variables** (`NETSEC_*` prefix)
3. **Configuration File** (YAML/JSON)
4. **Pydantic Defaults** (lowest priority)

### Environment Variable Format

```bash
# Flat settings
export NETSEC_DEBUG=true
export NETSEC_API_PORT=8443

# Nested settings (use __ delimiter)
export NETSEC_STORAGE__ENCRYPT_EVIDENCE_AT_REST=true
export NETSEC_CAPTURE__PROFILE=full_evidence
export NETSEC_SCOPE__ALLOWED_CIDRS='["10.0.0.0/8"]'
```

---

## Key Configuration Options

### Application Settings

#### `app_name`
- **Type:** string | **Default:** "NetSec Platform"
- **Env:** `NETSEC_APP_NAME` | **Restart:** NO
- **Description:** Application name displayed in UI and logs.

#### `debug`
- **Type:** boolean | **Default:** False
- **Env:** `NETSEC_DEBUG` | **Restart:** NO
- **Security:** May expose sensitive info in errors. Never enable in production.

#### `log_level`
- **Type:** string | **Default:** "INFO"
- **Allowed:** DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Env:** `NETSEC_LOG_LEVEL` | **Restart:** YES

#### `api_host`
- **Type:** string | **Default:** "127.0.0.1"
- **Env:** `NETSEC_API_HOST` | **Restart:** YES | **Security:** YES
- **Production:** Use 127.0.0.1 with reverse proxy.

#### `api_port`
- **Type:** integer | **Default:** 8000 | **Range:** 1-65535
- **Env:** `NETSEC_API_PORT` | **Restart:** YES | **Security:** YES

#### `api_key`
- **Type:** string or null | **Default:** None
- **Env:** `NETSEC_API_KEY` | **Restart:** YES | **Security:** YES
- **Note:** Secret value. Use environment variable or secret manager.

#### `session_timeout_minutes`
- **Type:** integer | **Default:** 60 | **Range:** 1-1440
- **Env:** `NETSEC_SESSION_TIMEOUT_MINUTES` | **Restart:** YES | **Security:** YES

#### `require_mfa`
- **Type:** boolean | **Default:** False
- **Env:** `NETSEC_REQUIRE_MFA` | **Restart:** YES | **Security:** YES
- **Production:** Enable for all deployments.

---

### Storage Configuration

#### `storage.base_path`
- **Type:** string | **Default:** "/var/netsec_platform/data"
- **Env:** `NETSEC_STORAGE__BASE_PATH` | **Restart:** YES
- **Requirements:** Must be writable, 10GB+ free space.

#### `storage.evidence_path`
- **Type:** string | **Default:** "evidence"
- **Env:** `NETSEC_STORAGE__EVIDENCE_PATH` | **Restart:** YES | **Security:** YES
- **Note:** Relative to base_path. Restrict permissions (700).

#### `storage.encrypt_evidence_at_rest`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_STORAGE__ENCRYPT_EVIDENCE_AT_REST` | **Restart:** YES | **Security:** YES
- **Production:** ALWAYS enable (true).

#### `storage.metadata_retention_days`
- **Type:** integer | **Default:** 30 | **Range:** 1-3650
- **Env:** `NETSEC_STORAGE__METADATA_RETENTION_DAYS` | **Restart:** NO

#### `storage.pcap_retention_days`
- **Type:** integer | **Default:** 7 | **Range:** 1-365
- **Env:** `NETSEC_STORAGE__PCAP_RETENTION_DAYS` | **Restart:** NO

#### `storage.evidence_retention_days`
- **Type:** integer | **Default:** 90 | **Range:** 1-3650
- **Env:** `NETSEC_STORAGE__EVIDENCE_RETENTION_DAYS` | **Restart:** NO | **Security:** YES

#### `storage.max_storage_gb`
- **Type:** float | **Default:** 100.0 | **Range:** 1-10000
- **Env:** `NETSEC_STORAGE__MAX_STORAGE_GB` | **Restart:** NO
- **Behavior:** Oldest data deleted when exceeded.

---

### Capture Configuration

#### `capture.profile`
- **Type:** enum | **Default:** "standard"
- **Env:** `NETSEC_CAPTURE__PROFILE` | **Restart:** YES | **Security:** YES
- **Allowed Values:**
  - `metadata_only` - No payloads (Profile A)
  - `standard` - Recommended default (Profile B)
  - `full_evidence` - Full payload capture (Profile C)

**Profile Details:**
- **metadata_only:** IP/port/proto/timestamps only. Minimal storage (~10%).
- **standard:** Flow metadata + protocol analysis. Moderate storage.
- **full_evidence:** Complete packets + evidence. Maximum storage. Requires confirmation.

#### `capture.interface`
- **Type:** string or null | **Default:** None (auto-discover)
- **Env:** `NETSEC_CAPTURE__INTERFACE` | **Restart:** YES
- **Examples:** eth0, wlan0, lo, any

#### `capture.ring_buffer_size_mb`
- **Type:** integer | **Default:** 512 | **Range:** 64-4096
- **Env:** `NETSEC_CAPTURE__RING_BUFFER_SIZE_MB` | **Restart:** YES
- **Production:** 512MB standard, 1024-2048MB high-throughput.

#### `capture.snap_length`
- **Type:** integer | **Default:** 65535 | **Range:** 68-65535
- **Env:** `NETSEC_CAPTURE__SNAP_LENGTH` | **Restart:** YES
- **Note:** Currently hardcoded to 65535 regardless of config.

#### `capture.max_packets_per_second`
- **Type:** integer | **Default:** 100000 | **Range:** 1000-1000000
- **Env:** `NETSEC_CAPTURE__MAX_PACKETS_PER_SECOND` | **Restart:** NO
- **Purpose:** Prevents overload during traffic spikes.

#### `capture.bpf_filter`
- **Type:** string or null | **Default:** None
- **Env:** `NETSEC_CAPTURE__BPF_FILTER` | **Restart:** YES
- **Example:** "port 80 or port 53", "not net 10.0.0.0/8"

---

### Scope Configuration (Authorization)

#### `scope.allowed_cidrs`
- **Type:** list[string] | **Default:** []
- **Env:** `NETSEC_SCOPE__ALLOWED_CIDRS` | **Restart:** NO | **Security:** YES
- **Purpose:** Authorized network ranges for testing.
- **Example:** ["10.10.0.0/16", "192.168.1.0/24"]

#### `scope.excluded_cidrs`
- **Type:** list[string] | **Default:** []
- **Env:** `NETSEC_SCOPE__EXCLUDED_CIDRS` | **Restart:** NO | **Security:** YES
- **Purpose:** Ranges excluded from testing.

#### `scope.allowed_domains`
- **Type:** list[string] | **Default:** []
- **Env:** `NETSEC_SCOPE__ALLOWED_DOMAINS` | **Restart:** NO | **Security:** YES

#### `scope.auth_reference`
- **Type:** string or null | **Default:** None
- **Env:** `NETSEC_SCOPE__AUTH_REFERENCE` | **Restart:** NO | **Security:** YES
- **Purpose:** Authorization document reference for audit trail.
- **Example:** "AUTH-2026-0042"

#### `scope.authz_type`
- **Type:** string | **Default:** "written_authorization"
- **Env:** `NETSEC_SCOPE__AUTHZ_TYPE` | **Restart:** NO | **Security:** YES
- **Production:** Always use "written_authorization".

---

### Emergency Security Stop (ESS)

#### `ess.enabled`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_ESS__ENABLED` | **Restart:** NO | **Security:** YES
- **Production:** NEVER disable.

#### `ess.require_confirmation`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_ESS__REQUIRE_CONFIRMATION` | **Restart:** NO | **Security:** YES
- **Purpose:** Prevents accidental activation.

#### `ess.lock_sensitive_evidence`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_ESS__LOCK_SENSITIVE_EVIDENCE` | **Restart:** NO | **Security:** YES
- **Behavior:** Locks credentials/tokens/cookies during emergency.

#### `ess.stop_active_tests`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_ESS__STOP_ACTIVE_TESTS` | **Restart:** NO | **Security:** YES

#### `ess.preserve_evidence`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_ESS__PRESERVE_EVIDENCE` | **Restart:** NO | **Security:** YES
- **Behavior:** Evidence preserved (not deleted) on ESS.

#### `ess.require_auth_for_recovery`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_ESS__REQUIRE_AUTH_FOR_RECOVERY` | **Restart:** NO | **Security:** YES

#### `ess.auto_recovery_timeout_minutes`
- **Type:** integer | **Default:** 0 (disabled)
- **Env:** `NETSEC_ESS__AUTO_RECOVERY_TIMEOUT_MINUTES` | **Restart:** NO | **Security:** YES
- **Production:** Keep 0 (manual recovery only).

---

### Controlled Testing Configuration

#### `controlled_test.enabled`
- **Type:** boolean | **Default:** False
- **Env:** `NETSEC_CONTROLLED_TEST__ENABLED` | **Restart:** YES | **Security:** YES
- **Production:** false for monitoring-only deployments.

#### `controlled_test.max_requests_per_second`
- **Type:** integer | **Default:** 10 | **Range:** 1-1000
- **Env:** `NETSEC_CONTROLLED_TEST__MAX_REQUESTS_PER_SECOND` | **Restart:** NO | **Security:** YES
- **Purpose:** Rate limiting for test requests.

#### `controlled_test.max_total_requests`
- **Type:** integer | **Default:** 1000 | **Range:** 1-1000000
- **Env:** `NETSEC_CONTROLLED_TEST__MAX_TOTAL_REQUESTS` | **Restart:** NO | **Security:** YES

#### `controlled_test.request_timeout_seconds`
- **Type:** integer | **Default:** 30 | **Range:** 1-300
- **Env:** `NETSEC_CONTROLLED_TEST__REQUEST_TIMEOUT_SECONDS` | **Restart:** NO | **Security:** YES

#### `controlled_test.test_duration_limit_minutes`
- **Type:** integer | **Default:** 60 | **Range:** 1-1440
- **Env:** `NETSEC_CONTROLLED_TEST__TEST_DURATION_LIMIT_MINUTES` | **Restart:** NO | **Security:** YES

#### `controlled_test.require_explicit_approval`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_CONTROLLED_TEST__REQUIRE_EXPLICIT_APPROVAL` | **Restart:** NO | **Security:** YES
- **Production:** ALWAYS true.

#### `controlled_test.validate_target_scope`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_CONTROLLED_TEST__VALIDATE_TARGET_SCOPE` | **Restart:** NO | **Security:** YES
- **Production:** NEVER disable. Critical safety control.

#### `controlled_test.fail_closed_on_error`
- **Type:** boolean | **Default:** True
- **Env:** `NETSEC_CONTROLLED_TEST__FAIL_CLOSED_ON_ERROR` | **Restart:** NO | **Security:** YES

---

## Configuration Interactions

### Storage Quota Chain
```
storage.max_storage_gb → storage.max_pcap_size_mb → storage.pcap_retention_days
```
When max_storage_gb reached: oldest PCAPs deleted first. At 110%, ESS triggered.

### Profile + Encryption Requirement
```yaml
capture.profile: "full_evidence"
storage.encrypt_evidence_at_rest: true  # REQUIRED
```
Full evidence profile requires encryption enabled.

### Scope Enforcement
```yaml
scope.allowed_cidrs: ["10.0.0.0/8"]
scope.excluded_cidrs: ["10.0.50.0/24"]
controlled_test.validate_target_scope: true
```
Tests allowed in 10.0.0.0/8 EXCEPT 10.0.50.0/24. Validated before every test.

### ESS Cascade Effect
When ESS activated:
1. Stop active tests
2. Halt exports
3. Lock sensitive evidence
4. Preserve all existing evidence
5. Record audit event

---

## Verification Methods

### Startup Logs
```
INFO: Configuration loaded successfully
INFO: Capture profile: standard
INFO: Evidence encryption: enabled
INFO: ESS: enabled
INFO: API listening on 127.0.0.1:8000
```

### API Status Check
```bash
curl -s http://127.0.0.1:8000/api/v1/status | jq
```

### Configuration Validation
```bash
python -c "from netsec_platform.config.settings import load_config; print(load_config())"
```

---

## Security-Critical Settings (18 Total)

| Setting | Risk if Weakened |
|---------|-----------------|
| `api_host`, `api_port` | Network exposure |
| `api_key` | Authentication bypass |
| `session_timeout_minutes` | Session hijacking |
| `require_mfa` | Account compromise |
| `storage.encrypt_evidence_at_rest` | Data breach |
| `capture.profile` | Sensitive data exposure |
| `scope.*` | Unauthorized testing |
| `ess.*` | Emergency response failure |
| `controlled_test.*` | Test safety violations |

**Production Requirement:** Review all security-critical settings before deployment.

---

## Partially Implemented Settings

These settings exist but have limited implementation:

1. **`capture.snap_length`** - Defined but hardcoded to 65535
2. **`storage.compression_enabled`** - Flag exists, compression not implemented
3. **`app.debug_mode`** - Config exists, logging always redacts sensitive data

---

## Source Code Reference

**Definition:** `src/netsec_platform/config/settings.py`

**Key Classes:**
- `NetSecConfig` - Main configuration
- `StorageConfig` - Storage settings
- `CaptureConfig` - Capture engine
- `ScopeConfig` - Authorization scope
- `ESSConfig` - Emergency stop
- `ControlledTestConfig` - Pentesting

**Consumed By:** All platform modules via dependency injection.
