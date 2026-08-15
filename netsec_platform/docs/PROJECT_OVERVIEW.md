# Network Security Visibility, Traffic Analysis, Evidence & Authorized Pentesting Platform

## Project Overview

A professional net-sec visibility, traffic-analysis, security-monitoring, penetration-testing-assistance, and incident-investigation platform.

## Core Design Philosophy

Build a layered platform:
```
Capture → Decode → Normalize → Flow Reconstruction → Correlation → Detection → Evidence → Investigation → Reporting
```

## Primary Analyst Objects

- Hosts
- Connections/Flows
- Domains
- Services
- Applications
- Auth events
- Sensitive Data artifacts
- Security findings
- Evidence
- Investigation cases

## Supported Environments

- Individual endpoints (workstations, servers)
- Full LANs and routed networks
- Network perimeters (firewalls/gateways)
- VPN gateways
- Cloud networks
- Kubernetes clusters
- Container environments
- Virtual/physical network interfaces
- Offline PCAP/PCAPNG analysis

## Architecture

### Phase 1 - Foundation
- Project structure
- Configuration system
- Logging
- Local database
- Packet capture engine
- PCAP import/export
- Basic protocol decoding
- Flow engine
- Basic UI
- ESS foundation

### Phase 2 - Network Intelligence
- DNS analysis
- HTTP/TLS analysis
- Host discovery
- Connection correlation
- Search and filtering
- Statistics

### Phase 3 - Security Analysis
- Security rules engine
- Encryption classification
- Sensitive data detection
- Credential/session/token/cookie detection
- JWT/API-key detection
- Custom pattern detection
- Findings with evidence references and remediation

### Phase 4 - Evidence and Investigation
- Evidence store and vault
- Evidence viewer with access controls
- Evidence hashing and integrity verification
- Audit logging
- Chain of custody
- Timeline and investigation cases
- Network graph visualization
- Reporting
- Emergency evidence locking

### Phase 5 - Web Security Analysis
- Application inventory
- Cookie security analysis
- Session security analysis
- Auth-flow analysis
- Security-header analysis
- Sensitive data flow mapping
- Web-security findings

### Phase 6 - Environment Integrations
- VPN analysis
- Kubernetes network telemetry
- Cloud flow logs
- Additional telemetry adapters

### Phase 7 - Controlled Testing
- Authorization reference tracking
- Scope configuration
- Target validation
- Explicit operator approval
- Rate limiting and timeouts
- Abort controls
- Audit trail
- Evidence association

### Phase 8 - Hardening
- High-throughput testing
- Parser fuzzing
- Security testing
- Emergency-stop reliability testing

## Emergency Security Stop (ESS)

The ESS is a first-class safety and containment mechanism that:
1. Stops packet capture
2. Stops sensitive data processing
3. Stops active tests
4. Stops exports
5. Preserves current evidence
6. Locks sensitive evidence access
7. Records the emergency-stop event

## Capture Profiles

### Profile A - Metadata Only
- No payloads retained
- Store metadata only
- No sensitive values stored

### Profile B - Standard Security Capture (Recommended)
- Network metadata
- Flow info
- PCAP according to configured limits
- Protocol metadata
- Security findings
- Sensitive detections
- Evidence references
- Sensitive values protected

### Profile C - Full Authorized Evidence Capture
- Full payload/evidence capture
- Requires explicit operator confirmation
- Prominent warning displayed
- Encryption at rest
- Access control
- Evidence auditing
- Retention limits
- Secure deletion
- Evidence integrity hashes

## Security Principles

1. **Evidence-based terminology**: Use "observed", "demonstrated", "exposed" rather than absolute claims
2. **No automatic exploitation**: Captured auth artifacts are evidence first
3. **Separation of concerns**: Passive monitoring vs active testing
4. **Fail-closed behavior**: System fails safely under error conditions
5. **Least privilege**: Role-based access control throughout
6. **Evidence integrity**: Cryptographic hashing and chain of custody
7. **Sensitive data protection**: Encryption at rest, controlled reveal, audit logging

## Success Criteria

An authorized security analyst can answer:

### Network Questions
- Which devices are communicating?
- Who is communicating with whom?
- What ports and protocols are being used?
- Which devices are new?
- Which services are exposed?

### DNS Questions
- What domains are being queried?
- Which DNS servers are used?
- Is suspicious DNS behavior present?

### HTTPS/TLS Questions
- Which HTTPS connections exist?
- What certificates are being used?
- What TLS versions and ciphers are present?

### Security Questions
- Which traffic is plaintext?
- Which credentials are exposed?
- Which cookies/sessions/tokens are exposed?
- Which sensitive info is exposed?

### Investigation Questions
- What happened and when?
- Which hosts were involved?
- What evidence proves the finding?
- Who accessed the evidence?
- Was an emergency security stop activated?

### Pentesting Questions
- What was the authorization scope?
- What evidence was collected?
- Which weaknesses were demonstrated?
- Can every active operation be terminated immediately?
