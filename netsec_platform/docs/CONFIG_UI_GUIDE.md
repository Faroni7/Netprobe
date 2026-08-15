# Configuration UI Guide

## Overview

The NetSec Platform now includes a secure, web-based configuration management interface accessible at `/settings`. This guide explains how to use it safely and effectively.

## Access Requirements

### Authentication
- Must be logged in with valid credentials
- Session must not be expired

### Authorization
Required permissions:
- `CONFIG_READ` - View configuration (all admins)
- `CONFIG_UPDATE` - Modify configuration (admin only)
- `CONFIG_RELOAD` - Reload configuration runtime (admin only)

**Note:** Regular analysts and read-only users cannot access configuration management.

## Getting Started

### 1. Navigate to Settings
From any page, click **Settings** in the left navigation menu.

### 2. Browse Categories
Configuration is organized into logical categories:
- **General** - Application environment, logging, timezone
- **Network** - API exposure, CORS, rate limiting
- **Traffic Capture** - Interface selection, capture profiles, buffers
- **Evidence** - Storage paths, encryption, retention
- **Authentication** - Session timeouts, login policies
- **Audit Logging** - Log retention, destinations
- **Authorized Pentesting** - Testing controls, rate limits
- **Emergency Security Stop** - ESS configuration
- **Advanced** - Additional settings

### 3. Search Settings
Use the search bar to quickly find settings by:
- Setting name (e.g., "profile")
- Description (e.g., "encryption")
- Full path (e.g., "capture.profile")

## Understanding Settings

Each setting displays:
- **Name** - Human-readable label
- **Current Value** - Effective value from all sources
- **Type Indicator**:
  - 🔒 Locked (cannot modify)
  - ⚠️ Security-critical
  - 🔄 Restart required badge
- **Description** - What the setting does
- **Source** - Where the value comes from:
  - DEFAULT - Built-in default
  - CONFIG_FILE - From netsec.config.yaml
  - ENVIRONMENT - Environment variable override
  - RUNTIME - Changed via API

## Making Changes

### Step 1: Edit Values
Click or toggle any setting to change its value:
- **Text fields** - Type new value
- **Numbers** - Enter numeric value within min/max range
- **Booleans** - Toggle switch on/off
- **Enums** - Select from dropdown
- **Arrays** - Comma-separated list
- **Secrets** - Password field (redacted)

### Step 2: Review Changes
When you have unsaved changes:
- Yellow indicator shows pending modifications
- **Cancel** button discards all changes
- **Save Changes** button validates and applies

### Step 3: Validate
Before saving, the system:
1. Checks value types and ranges
2. Validates against schema
3. Rejects invalid configurations
4. Shows error messages for issues

### Step 4: Save
Click **Save Changes** to:
1. Send changes to backend
2. Apply atomically (all-or-nothing)
3. Update configuration file
4. Log audit event
5. Reload if runtime-reloadable

### Step 5: Handle Restart
If changes require restart:
- Badge shows "Restart Required"
- Application continues running with old values
- Restart manually when convenient
- Some settings apply immediately (marked "Hot Reloadable")

## Security-Critical Settings

Settings marked ⚠️ affect security boundaries:

### Evidence Encryption
- `evidence.encryption_enabled`
- **Impact:** Disabling exposes evidence at rest
- **Recommendation:** Always enable in production

### Authorization Requirements
- `testing.require_authorization`
- `testing.require_scope`
- **Status:** 🔒 Locked (cannot disable)
- **Reason:** Safety control for pentesting

### Emergency Security Stop
- `ess.enabled`
- **Status:** 🔒 Locked (cannot disable)
- **Reason:** Critical safety mechanism

### Session Timeouts
- `auth.session_timeout_minutes`
- **Impact:** Longer = more session hijack risk
- **Recommendation:** 60 minutes or less

## Secret Management

Secrets (passwords, keys, tokens) are handled specially:

### Viewing Secrets
- Displayed as `••••••••` by default
- Click eye icon to reveal temporarily
- Access is audited
- Auto-hides after period

### Changing Secrets
- Leave blank to keep current value
- Enter new value to replace
- Stored encrypted at rest
- Never shown in logs

### Best Practices
1. Set secrets via environment variables in production
2. Use secret managers (Vault, AWS Secrets Manager)
3. Rotate regularly
4. Audit access frequently

## Configuration Sources

Values come from multiple sources (highest precedence first):

1. **Runtime Updates** - Changes via API/UI
2. **Environment Variables** - NETSEC_* variables
3. **Configuration File** - config/netsec.config.yaml
4. **Built-in Defaults** - Hardcoded fallbacks

### Example Precedence

```yaml
# Config file says:
capture.profile: standard

# But environment variable set:
NETSEC_CAPTURE_PROFILE=full_evidence

# Effective value: full_evidence
```

## Validation Errors

If validation fails, you'll see:

```
Validation failed: capture.buffer_size_mb must be between 64 and 4096
```

Common errors:
- **Type mismatch** - String where number expected
- **Out of range** - Value exceeds min/max
- **Invalid enum** - Value not in allowed list
- **Missing required** - Required field empty
- **Format error** - Invalid email, URL, etc.

## Audit Logging

Every configuration change is logged:

```json
{
  "timestamp": "2026-08-12T14:35:02Z",
  "actor": "admin",
  "action": "CONFIG_UPDATE",
  "path": "app.log_level",
  "old_value": "info",
  "new_value": "debug",
  "restart_required": false
}
```

**Note:** Secret values are NEVER logged.

## Runtime Reload vs Restart

### Runtime Reload (Hot)
These settings apply immediately:
- `app.log_level`
- `auth.session_timeout_minutes`
- `audit.retention_days`
- Most detection thresholds

No restart needed - changes take effect within seconds.

### Restart Required (Cold)
These need application restart:
- `app.host` - Bind address
- `app.port` - Listening port
- `capture.profile` - Data retention mode
- `evidence.storage_path` - Storage location
- Network bindings
- TLS certificates

Restart command:
```bash
sudo systemctl restart netsec-platform
```

## Troubleshooting

### "Permission Denied"
**Cause:** Insufficient privileges  
**Solution:** Contact administrator for CONFIG_UPDATE permission

### "Validation Failed"
**Cause:** Invalid value  
**Solution:** Check error message, correct the value

### "Setting Locked"
**Cause:** Security-critical setting  
**Solution:** Cannot modify - this is intentional

### Changes Not Persisting
**Cause:** Environment variable override  
**Solution:** Update environment variable or remove it

### Restart Required Badge Missing
**Cause:** Metadata not loaded  
**Solution:** Refresh page to reload schema

### Secrets Not Saving
**Cause:** Trying to save empty secret  
**Solution:** Leave blank to keep current, or enter full new value

## Export/Import (Future)

Planned features:
- Export sanitized configuration (secrets omitted)
- Import validated configuration
- Diff between environments
- Version history

## Production Checklist

Before deploying configuration changes to production:

- [ ] Test changes in development/testing first
- [ ] Review security-critical changes with team
- [ ] Verify backup exists
- [ ] Schedule maintenance window if restart required
- [ ] Document change in change management system
- [ ] Monitor after deployment
- [ ] Verify audit logs show expected changes

## Configuration File Location

Default locations:
- **Linux:** `/var/netsec_platform/config/netsec.config.yaml`
- **macOS:** `/usr/local/etc/netsec_platform/config.yaml`
- **Windows:** `C:\ProgramData\NetSecPlatform\config.yaml`

Can be overridden with:
```bash
NETSEC_CONFIG_PATH=/custom/path/config.yaml
```

## Related Documentation

- `CONFIGURATION_REFERENCE.md` - Complete technical reference
- `config/example.config.yaml` - Example configuration file
- `docs/DEPLOYMENT.md` - Deployment procedures

## Support

For configuration issues:
1. Check validation error messages
2. Review CONFIGURATION_REFERENCE.md
3. Examine audit logs
4. Contact security team for locked settings

---

**Last Updated:** 2026-08-12  
**Version:** 1.0  
**Applies to:** NetSec Platform v1.0+
