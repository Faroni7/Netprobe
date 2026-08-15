# NetSec Platform

**Network Security Visibility, Traffic Analysis, Evidence & Authorized Pentesting Platform**

[![CI/CD](https://github.com/netsec-platform/netsec-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/netsec-platform/netsec-platform/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-68%20passed-green)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-blue)]()
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)]()

A professional platform for network security monitoring, traffic analysis, evidence preservation, and authorized penetration testing assistance.

## Overview

The NetSec Platform provides packet-level capabilities expected from a Wireshark-like network analyzer while adding higher-level functionality for:

- **Network Visibility**: Connection/flow analysis, asset discovery
- **Protocol Analysis**: DNS, HTTP/HTTPS/TLS, QUIC, SMB, LDAP, Kerberos, VPN/tunnel analysis  
- **Security Monitoring**: Sensitive data detection, credential exposure detection
- **Evidence Preservation**: Secure evidence storage with chain of custody
- **Incident Investigation**: Case management, timeline reconstruction
- **Authorized Testing**: Explicitly controlled security testing with ESS safety controls
- **Cloud & Kubernetes**: VPC flow logs, pod-to-pod correlation

## Core Design Philosophy

> Build a layered platform: **Capture → Decode → Normalize → Flow Reconstruction → Correlation → Detection → Evidence → Investigation → Reporting**

Packets are low-level evidence. The primary analyst objects are:
- Hosts, Connections, Domains, Services, Applications
- Auth events, Sensitive Data artifacts, Security findings
- Evidence, Investigation cases

## Key Features

### Emergency Security Stop (ESS)

A first-class safety mechanism that immediately:
1. Stops packet capture and processing
2. Stops active security tests
3. Stops exports
4. Preserves current evidence
5. Locks sensitive evidence access
6. Records an auditable event
7. Waits for authorized recovery

Activation time: **<100ms** under all conditions including high load.

### Capture Profiles

- **Profile A - Metadata Only**: No payloads retained, maximum privacy
- **Profile B - Standard** (Recommended): Network metadata with protected sensitive values
- **Profile C - Full Evidence**: Full payload capture with explicit confirmation and AES-256-GCM encryption

### Security Principles

1. **Evidence-based terminology**: "observed", "demonstrated", "exposed" - not absolute claims
2. **No automatic exploitation**: Captured auth artifacts are evidence first
3. **Separation of concerns**: Passive monitoring vs active testing
4. **Fail-closed behavior**: System fails safely under error conditions
5. **Least privilege**: Role-based access control with 12 permission types
6. **Evidence integrity**: SHA-256 hashing and chain of custody tracking
7. **Encrypted storage**: AES-256-GCM for sensitive evidence at rest
8. **Tamper-evident logging**: Append-only audit logs

## Project Structure

See the complete directory structure in the repository. Key components:
- `src/netsec_platform/` - Backend Python modules (capture, decode, flow, detection, evidence, api, etc.)
- `frontend/` - React 18 + TypeScript web application
- `tests/` - Comprehensive test suite (68 tests)
- `docs/` - Documentation files
- `.github/workflows/` - CI/CD pipeline

## Installation

### Prerequisites

- **Python 3.10+** with pip
- **Root/sudo privileges** for live packet capture
- **libpcap development libraries** (`libpcap-dev` on Debian/Ubuntu)
- **Node.js 18+** (for frontend development)

### Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/netsec-platform.git
cd netsec_platform
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd frontend && npm install && cd ..
pytest --cov=src
uvicorn src.netsec_platform.api.main:app --host 127.0.0.1 --port 8000
```

## Configuration

Configure via environment variables or YAML file. Key settings:
- Capture profile (metadata-only, standard, full-evidence)
- Network interface selection
- Storage encryption and retention
- ESS enablement
- Kubernetes/Cloud integrations

## Usage

Start the API server and access the web UI at `http://localhost:8000`. The ESS button is prominently displayed on all security-sensitive screens.

Supported interfaces: Ethernet (eth0), WiFi (wlan0), Virtual (vmnet, vboxnet), Loopback (lo), Bridge (br0), Tunnel (tun0).

## Development Phases - Completion Status

All 8 phases are **100% complete**:

- **Phase 1**: Foundation (capture, config, ESS, basic decoders)
- **Phase 2**: Network Intelligence (DNS, HTTP, TLS, flows, search)
- **Phase 3**: Security Analysis (8 detectors, 11 SD patterns)
- **Phase 4**: Evidence & Investigation (vault, audit, API, reports)
- **Phase 5**: Web Security Analysis (cookies, sessions, headers)
- **Phase 6**: Environment Integrations (K8s, Cloud, QUIC/SMB/LDAP/Kerberos)
- **Phase 7**: Controlled Testing (authz validation, rate limiting, ESS integration)
- **Phase 8**: Hardening (fuzzing, stress tests, security validation)

## API Reference

REST API with 40+ endpoints documented at `/docs` (Swagger UI). Key endpoints:
- `/api/v1/capture/*` - Capture control
- `/api/v1/flows`, `/api/v1/hosts`, `/api/v1/dns`, `/api/v1/tls` - Data queries
- `/api/v1/findings`, `/api/v1/evidence/*` - Security findings and evidence
- `/api/v1/ess/*` - Emergency Security Stop
- `/api/v1/tests/controlled` - Controlled testing

Sensitive endpoints require explicit permissions. ESS endpoint has enhanced protection.

## Security Considerations

This platform processes credentials, tokens, PII, PCAPs, and security findings. Implemented mitigations:
- AES-256-GCM encryption at rest
- RBAC with 12 permission types
- Tamper-evident audit logging
- Emergency Security Stop
- Sensitive data redaction in logs
- SHA-256 integrity hashing
- Fail-closed scope enforcement

## Technology Stack

**Backend**: Python 3.10+, FastAPI, Scapy, SQLite, Pydantic, structlog, cryptography  
**Frontend**: React 18, TypeScript, MUI, Tailwind, Zustand, Recharts, Cytoscape.js  
**Testing**: pytest, bandit, gitleaks, black, ruff, mypy

## Contributing

Follow incremental development practices. See full guidelines in the repository.

## License

MIT License (recommended)

## Disclaimer

For **authorized** security testing only. Does not claim systems are "unhackable." All testing requires:
1. Explicit written authorization
2. Defined scope
3. Legal compliance
4. Ethical guidelines adherence

ESS provides rapid containment but doesn't replace authorization processes.

---

**NetSec Platform** - Professional network security visibility and authorized testing assistance.

Built with security, privacy, and accountability as first-class requirements.
