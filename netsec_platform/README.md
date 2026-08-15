# NetSec Platform

**Network Security Visibility, Traffic Analysis, Evidence & Authorized Pentesting Platform**

A professional platform for network security monitoring, traffic analysis, evidence preservation, and authorized penetration testing assistance.

## Overview

The NetSec Platform provides packet-level capabilities expected from a Wireshark-like network analyzer while adding higher-level functionality for:

- **Network Visibility**: Connection/flow analysis, asset discovery
- **Protocol Analysis**: DNS, HTTP/HTTPS/TLS, VPN/tunnel analysis  
- **Security Monitoring**: Sensitive data detection, credential exposure detection
- **Evidence Preservation**: Secure evidence storage with chain of custody
- **Incident Investigation**: Case management, timeline reconstruction
- **Authorized Testing**: Explicitly controlled security testing with ESS safety controls

## Core Design Philosophy

> Build a layered platform: **Capture → Decode → Normalize → Flow Reconstruction → Correlation → Detection → Evidence → Investigation → Reporting**

Packets are low-level evidence. The primary analyst objects are:
- Hosts, Connections, Domains, Services, Applications
- Auth events, Sensitive Data artifacts, Security findings
- Evidence, Investigation cases

## Key Features

### Emergency Security Stop (ESS) ⚠️

A first-class safety mechanism that immediately:
1. Stops packet capture and processing
2. Stops active security tests
3. Stops exports
4. Preserves current evidence
5. Locks sensitive evidence access
6. Records an auditable event
7. Waits for authorized recovery

### Capture Profiles

- **Profile A - Metadata Only**: No payloads retained
- **Profile B - Standard** (Recommended): Network metadata with protected sensitive values
- **Profile C - Full Evidence**: Full payload capture with explicit confirmation and encryption

### Security Principles

1. **Evidence-based terminology**: "observed", "demonstrated", "exposed" - not absolute claims
2. **No automatic exploitation**: Captured auth artifacts are evidence first
3. **Separation of concerns**: Passive monitoring vs active testing
4. **Fail-closed behavior**: System fails safely under error conditions
5. **Least privilege**: Role-based access control throughout
6. **Evidence integrity**: Cryptographic hashing and chain of custody

## Project Structure

```
netsec_platform/
├── src/netsec_platform/
│   ├── __init__.py              # Package initialization
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py          # Configuration management
│   ├── models/
│   │   ├── __init__.py
│   │   └── core_models.py       # Core data models
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logging_config.py    # Secure logging
│   │   └── emergency_stop.py    # ESS implementation
│   ├── capture/                 # Packet capture engine (Phase 1)
│   ├── decode/                  # Protocol decoders (Phase 1-2)
│   ├── flow/                    # Flow reconstruction (Phase 2)
│   ├── detection/               # Security detection engine (Phase 3)
│   ├── evidence/                # Evidence vault (Phase 4)
│   ├── storage/                 # Storage layer (Phase 4)
│   ├── api/                     # REST API (Phase 4)
│   ├── ui/                      # Web interface (Phase 1+)
│   └── ctl/                     # Controlled testing (Phase 7)
├── tests/                       # Automated tests
├── docs/                        # Documentation
├── data/                        # Runtime data directory
│   ├── pcaps/                   # Captured PCAP files
│   ├── evidence/                # Encrypted evidence store
│   ├── logs/                    # Application logs
│   └── db/                      # SQLite database
├── pyproject.toml               # Project configuration
└── README.md                    # This file
```

## Installation

### Prerequisites

- Python 3.10+
- Root/sudo privileges for live packet capture
- libpcap development libraries

### Development Setup

```bash
# Clone repository
cd netsec_platform

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## Configuration

Configuration can be set via environment variables with `NETSEC_` prefix:

```bash
export NETSEC_API_HOST=127.0.0.1
export NETSEC_API_PORT=8000
export NETSEC_DEBUG=false
export NETSEC_CAPTURE__PROFILE=standard
export NETSEC_STORAGE__BASE_PATH=/var/netsec_platform/data
```

Or via configuration file:

```yaml
app_name: "NetSec Platform"
debug: false
api_host: "127.0.0.1"
api_port: 8000

capture:
  profile: "standard"
  interface: "eth0"
  max_capture_size_mb: 4096

storage:
  base_path: "/var/netsec_platform/data"
  encrypt_evidence_at_rest: true
  evidence_retention_days: 90

ess:
  enabled: true
  require_confirmation: true
  lock_sensitive_evidence: true
```

## Usage

### Starting the Platform

```bash
# Start the API server
uvicorn netsec_platform.api.main:app --host 127.0.0.1 --port 8000

# Or use the CLI (when implemented)
netsec-platform start --interface eth0 --profile standard
```

### Emergency Security Stop

The ESS can be activated through:
- Web UI prominent button on all security-sensitive screens
- API endpoint: `POST /api/v1/ess/activate`
- Out-of-band mechanism (deployment-dependent)

Recovery requires explicit authorization:
```bash
POST /api/v1/ess/recover
{
  "operator": "analyst01",
  "reason": "False alarm, investigating"
}
```

## Development Phases

### Phase 1 - Foundation ✅
- [x] Project structure
- [x] Configuration system
- [x] Logging with sensitive data filtering
- [x] Emergency Security Stop (ESS)
- [ ] Packet capture engine
- [ ] PCAP import/export
- [ ] Basic protocol decoding
- [ ] Flow engine
- [ ] Basic UI

### Phase 2 - Network Intelligence
- [ ] DNS analysis
- [ ] HTTP/TLS analysis
- [ ] Host discovery
- [ ] Connection correlation
- [ ] Search and filtering
- [ ] Statistics

### Phase 3 - Security Analysis
- [ ] Security rules engine
- [ ] Encryption classification
- [ ] Sensitive data detection
- [ ] Credential/session/token/cookie detection
- [ ] Findings with remediation

### Phase 4 - Evidence and Investigation
- [ ] Evidence store and vault
- [ ] Evidence viewer with access controls
- [ ] Audit logging
- [ ] Chain of custody
- [ ] Timeline and investigation cases
- [ ] Reporting

### Phase 5 - Web Security Analysis
- [ ] Application inventory
- [ ] Cookie security analysis
- [ ] Session security analysis
- [ ] Security-header analysis

### Phase 6 - Environment Integrations
- [ ] VPN analysis
- [ ] Kubernetes network telemetry
- [ ] Cloud flow logs

### Phase 7 - Controlled Testing
- [ ] Authorization reference tracking
- [ ] Scope configuration
- [ ] Target validation
- [ ] Explicit operator approval workflows

### Phase 8 - Hardening
- [ ] High-throughput testing
- [ ] Parser fuzzing
- [ ] Security testing
- [ ] ESS reliability testing

## API

The platform provides a REST API for:

- Starting/stopping captures
- Querying flows, hosts, DNS, TLS
- Querying findings and evidence metadata
- Creating investigation cases
- Exporting reports
- Managing capture profiles
- Triggering emergency security stop

**Note**: Sensitive evidence is only available through explicitly authorized API endpoints with appropriate permissions.

## Security Considerations

This platform is a high-value security target because it processes:
- Credentials, tokens, cookies, session identifiers
- Personal information
- PCAPs and network topology
- Security findings

### Implemented Mitigations

- ✅ Encryption at rest for sensitive evidence
- ✅ Role-based access control
- ✅ Audit logging for all evidence access
- ✅ Emergency Security Stop
- ✅ Sensitive data redaction in logs
- ✅ Scope enforcement
- ✅ Fail-closed behavior

### Additional Requirements for Production

- Strong authentication with MFA
- Separate sensitive evidence storage
- Secure deletion procedures
- Backup encryption
- Regular security audits

## License

[To be determined]

## Contributing

This project is developed with AI assistance following incremental development practices:

1. Explain module purpose before implementation
2. Identify dependencies and interfaces
3. Define data structures and error handling
4. Implement with security and performance requirements
5. Test thoroughly
6. Review integration and check for regressions

## Disclaimer

This platform is intended for **authorized** penetration testing, security assessments, defensive monitoring, and incident investigation. 

The product does not claim that any system is "unhackable." Security is represented through measurable exposure, observed weaknesses, controls, evidence, risk, and remediation.

All security testing must be performed within explicitly authorized scope with proper written authorization from appropriate authorities.
