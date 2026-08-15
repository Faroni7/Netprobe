# Configuration Guide

Administrator-friendly guide for configuring the NetSec Platform.

## Quick Start

### 1. Copy Example Configuration
```bash
cp config/example.config.yaml config/config.yaml
```

### 2. Edit Configuration
```bash
vim config/config.yaml
```

Key settings to change:
- `api_host`: Set to `0.0.0.0` for remote access (with firewall)
- `storage.base_path`: Adjust if needed
- `capture.interface`: Set your network interface (e.g., `eth0`)
- `capture.profile`: Choose `metadata_only`, `standard`, or `full_evidence`

### 3. Set Environment Variables (Optional)
```bash
export NETSEC_API_KEY="<your-secret-key>"
export NETSEC_STORAGE__ENCRYPT_EVIDENCE_AT_REST=true
export NETSCOPE__ALLOWED_CIDRS='["10.0.0.0/8"]'
```

### 4. Start Platform
```bash
uvicorn netsec_platform.api.main:app --host 127.0.0.1 --port 8000
```

---

## Configuration Sources

The platform reads configuration from multiple sources (highest priority first):

1. **CLI Arguments** - `--config /path/to/config.yaml`
2. **Environment Variables** - `NETSEC_*` prefix
3. **Configuration File** - YAML format
4. **Built-in Defaults** - Safe defaults for all settings

### Environment Variable Format

Use `NETSEC_` prefix and `__` for nested keys:

```bash
# Simple settings
export NETSEC_DEBUG=true
export NETSEC_API_PORT=8443

# Nested settings
export NETSEC_CAPTURE__PROFILE=standard
export NETSEC_STORAGE__ENCRYPT_EVIDENCE_AT_REST=true
export NETSEC_SCOPE__ALLOWED_CIDRS='["10.10.0.0/16"]'
```

---

## Essential Settings

### Must Configure for Production

| Setting | Recommended Value | Why |
|---------|------------------|-----|
| `api_host` | `127.0.0.1` | Security - use reverse proxy |
| `api_key` | `<strong-random-key>` | API authentication |
| `storage.encrypt_evidence_at_rest` | `true` | Evidence protection |
| `capture.profile` | `standard` | Balance visibility/privacy |
| `ess.enabled` | `true` | Safety mechanism |
| `require_mfa` | `true` | Account security |
| `scope.allowed_cidrs` | `[your-networks]` | Testing scope |
| `controlled_test.enabled` | `false` | Unless actively pentesting |

### Capture Profiles

Choose based on your use case:

**metadata_only** (Profile A)
- Minimal data retention
- No packet payloads
- Best for: Privacy-sensitive environments, compliance

**standard** (Profile B) - RECOMMENDED
- Full flow metadata
- Protocol analysis
- Sensitive values masked
- Best for: Standard security monitoring

**full_evidence** (Profile C)
- Complete packet capture
- All evidence preserved
- Requires: Explicit confirmation, encryption enabled
- Best for: Authorized pentesting, forensics

---

## Security-Critical Settings

These settings directly affect security. Review carefully:

### Network Exposure
```yaml
api_host: "127.0.0.1"  # Change to 0.0.0.0 only with firewall
api_port: 8000         # Use reverse proxy for 443
```

### Authentication
```yaml
api_key: <SET_VIA_ENV>              # Never in config file
session_timeout_minutes: 60         # Reduce for high-security
require_mfa: true                   # Enable in production
```

### Evidence Protection
```yaml
storage:
  encrypt_evidence_at_rest: true    # ALWAYS enable
  evidence_retention_days: 90       # Adjust per compliance
```

### Emergency Stop
```yaml
ess:
  enabled: true                     # NEVER disable
  require_confirmation: true        # Prevent accidents
  lock_sensitive_evidence: true     # Lock creds on emergency
```

### Testing Scope (Critical for Pentesting)
```yaml
scope:
  allowed_cidrs: ["10.10.0.0/16"]   # Your authorized networks
  excluded_cidrs: ["10.10.50.0/24"] # Off-limits networks
  auth_reference: "AUTH-2026-0042"  # Authorization document
  authz_type: "written_authorization"

controlled_test:
  enabled: false                    # Enable only for active tests
  validate_target_scope: true       # NEVER disable
  require_explicit_approval: true   # Always require approval
```

---

## Common Configuration Scenarios

### Scenario 1: Development Setup
```yaml
app_name: "NetSec Platform - Dev"
debug: true
log_level: "DEBUG"
api_host: "127.0.0.1"
api_port: 8000

storage:
  base_path: "/tmp/netsec_dev"
  encrypt_evidence_at_rest: false  # OK for local dev

capture:
  profile: "metadata_only"
  interface: "lo"  # Localhost only
```

### Scenario 2: Production Monitoring
```yaml
app_name: "NetSec Platform - Production"
debug: false
log_level: "INFO"
api_host: "127.0.0.1"
api_port: 8000
require_mfa: true

storage:
  base_path: "/var/netsec_platform/data"
  encrypt_evidence_at_rest: true
  max_storage_gb: 500.0

capture:
  profile: "standard"
  interface: "eth0"
  ring_buffer_size_mb: 1024

ess:
  enabled: true
  require_confirmation: true
```

### Scenario 3: Authorized Pentesting
```yaml
capture:
  profile: "full_evidence"

storage:
  encrypt_evidence_at_rest: true
  evidence_retention_days: 365

scope:
  allowed_cidrs: ["10.10.0.0/16", "192.168.1.0/24"]
  excluded_ips: ["10.10.50.1", "10.10.50.2"]  # Critical systems
  allowed_domains: ["portal.example.com", "api.example.com"]
  auth_reference: "AUTH-2026-0042"
  authz_type: "written_authorization"
  testing_start: "2026-08-10T09:00:00Z"
  testing_end: "2026-08-20T17:00:00Z"

controlled_test:
  enabled: true
  max_requests_per_second: 10
  require_explicit_approval: true
  validate_target_scope: true
  fail_closed_on_error: true
```

### Scenario 4: High-Throughput Capture
```yaml
capture:
  profile: "metadata_only"  # Reduce storage
  interface: "any"
  ring_buffer_size_mb: 2048
  max_packets_per_second: 500000
  bpf_filter: "port 80 or port 443 or port 53"  # Filter traffic

storage:
  max_storage_gb: 1000.0
  pcap_retention_days: 3
  metadata_retention_days: 30
```

---

## Runtime Configuration Changes

### Can Change Without Restart
- `log_level` - Via API or signal
- `capture.max_packets_per_second` - Via API
- `storage.max_storage_gb` - Via API
- Most detection thresholds
- Rate limits

### Require Restart
- `api_host`, `api_port`
- `storage.base_path` and sub-paths
- `capture.profile`
- `capture.interface`
- `ess.enabled`
- Encryption settings
- All scope settings

---

## Verification

### Check Configuration on Startup
Look for these log messages:
```
INFO: Configuration loaded successfully
INFO: Capture profile: standard
INFO: Evidence encryption: enabled
INFO: ESS: enabled
INFO: API listening on 127.0.0.1:8000
INFO: Scope: 2 allowed CIDRs configured
```

### Query Runtime Configuration
```bash
curl -s http://127.0.0.1:8000/api/v1/status | jq
```

### Validate Configuration File
```bash
python -c "from netsec_platform.config.settings import load_config; cfg = load_config('config/config.yaml'); print('Valid')"
```

---

## Troubleshooting

### Application Won't Start
1. Check YAML syntax: `python -c "import yaml; yaml.safe_load(open('config.yaml'))"`
2. Verify paths exist and are writable
3. Check port not in use: `netstat -tlnp | grep 8000`
4. Review logs for specific errors

### Packet Capture Fails
1. Verify interface name: `ip link show`
2. Check permissions (need root/capabilities)
3. Ensure interface supports promiscuous mode
4. Try different interface or `any`

### Evidence Encryption Issues
1. Verify key path exists and is readable
2. Check key file permissions (600)
3. Ensure cryptography library installed
4. Review startup logs for encryption status

### ESS Not Responding
1. Verify `ess.enabled: true`
2. Check application not frozen (high CPU/memory)
3. Review system resources
4. Restart application if needed

### Controlled Tests Rejected
1. Verify `controlled_test.enabled: true`
2. Check target within `scope.allowed_cidrs`
3. Ensure `auth_reference` set
4. Confirm authorization period valid

---

## Backup and Recovery

### Backup Configuration
```bash
cp config/config.yaml config/config.yaml.backup-$(date +%Y%m%d)
cp -r /var/netsec_platform/data /backup/netsec_data-$(date +%Y%m%d)
```

### Restore Configuration
```bash
cp config/config.yaml.backup config/config.yaml
cp -r /backup/netsec_data /var/netsec_platform/data
chown -R netsec:netsec /var/netsec_platform/data
```

### Disaster Recovery
1. Install platform on new system
2. Restore configuration file
3. Restore data directory
4. Restore encryption keys from secure backup
5. Update any IP/host-specific settings
6. Start platform and verify

---

## Security Best Practices

1. **Never commit secrets** - Use environment variables or secret managers
2. **Enable encryption** - Always `encrypt_evidence_at_rest: true` in production
3. **Restrict API access** - Use `api_host: 127.0.0.1` with reverse proxy
4. **Enable MFA** - Set `require_mfa: true`
5. **Define scope** - Always configure `allowed_cidrs` for pentesting
6. **Keep ESS enabled** - Never disable emergency stop
7. **Regular rotation** - Rotate API keys and encryption keys periodically
8. **Monitor logs** - Watch for unauthorized access attempts
9. **Backup securely** - Encrypt backups, store separately
10. **Update regularly** - Keep dependencies current

---

## Configuration Reference

For complete technical details including all 47 options, see:
- [CONFIGURATION_REFERENCE.md](CONFIGURATION_REFERENCE.md) - Full technical reference
- [example.config.yaml](../config/example.config.yaml) - Complete example with all settings

---

## Support

For configuration issues:
1. Check logs in `storage.log_path`
2. Verify configuration syntax
3. Test with minimal config, add settings incrementally
4. Consult CONFIGURATION_REFERENCE.md for option details
5. Review security-critical settings if unexpected behavior
