# BlackBox Recon Threat Model

## 1. Overview

This document describes the security threats, attack vectors, and mitigations for BlackBox Recon. Understanding these threats helps operators deploy and use the tool securely.

## 2. Assets

### 2.1 Primary Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Scan Results | Discovered endpoints, vulnerabilities | HIGH |
| Target List | Systems being tested | HIGH |
| Database | SQLite file with all data | HIGH |
| API Keys/Tokens | Authentication credentials | CRITICAL |
| Configuration | Rate limits, proxy settings | MEDIUM |

### 2.2 Secondary Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Source Code | Application logic | LOW |
| Logs | Operational records | MEDIUM |
| Export Files | Generated reports | HIGH |

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    External Zone (Untrusted)                │
│                                                             │
│    ┌─────────────┐                                          │
│    │   Target    │◄────── Scanning Activity                 │
│    │   Systems   │                                          │
│    └─────────────┘                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                            │
                    [Network Boundary]
                            │
┌─────────────────────────────────────────────────────────────┐
│                    DMZ Zone (Limited Trust)                 │
│                                                             │
│    ┌─────────────┐     ┌─────────────┐                      │
│    │   Load      │     │   WAF/      │                      │
│    │   Balancer  │────►│   Firewall  │                      │
│    └─────────────┘     └─────────────┘                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                            │
                    [Authentication Boundary]
                            │
┌─────────────────────────────────────────────────────────────┐
│                    Internal Zone (Trusted)                  │
│                                                             │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐               │
│  │ Frontend  │  │  Backend  │  │ Database  │               │
│  │   (React) │  │ (FastAPI) │  │ (SQLite)  │               │
│  └───────────┘  └───────────┘  └───────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 4. Threat Actors

### 4.1 External Attackers

**Motivation:** Gain access to scan results, compromise scanning infrastructure

**Capabilities:**
- Network-based attacks
- Web application exploitation
- Social engineering

**Threats:**
| ID | Threat | Impact | Likelihood |
|----|--------|--------|------------|
| T01 | Unauthorized API access | HIGH | MEDIUM |
| T02 | SQL injection via input | HIGH | LOW |
| T03 | XSS against UI users | MEDIUM | LOW |
| T04 | DoS against scanner | MEDIUM | MEDIUM |

### 4.2 Malicious Insiders

**Motivation:** Steal sensitive findings, sabotage operations

**Capabilities:**
- Authorized access
- Knowledge of systems
- Physical access

**Threats:**
| ID | Threat | Impact | Likelihood |
|----|--------|--------|------------|
| T05 | Data exfiltration | HIGH | LOW |
| T06 | Credential theft | HIGH | LOW |
| T07 | Evidence tampering | HIGH | LOW |

### 4.3 Compromised Targets

**Motivation:** Counter-attack, fingerprint scanner

**Capabilities:**
- Respond to scans
- Log scanner signatures
- Potential exploit delivery

**Threats:**
| ID | Threat | Impact | Likelihood |
|----|--------|--------|------------|
| T08 | Scanner fingerprinting | MEDIUM | HIGH |
| T09 | Reverse connection attempt | HIGH | LOW |
| T10 | Malicious response payload | HIGH | LOW |

## 5. Attack Vectors

### 5.1 API Attacks

#### A1: Unauthorized Access
- **Vector:** Direct API calls without authentication
- **Mitigation:** 
  - Enable JWT authentication (TODO)
  - Implement API key validation
  - Use CORS restrictions

#### A2: Input Injection
- **Vector:** Malformed target URLs, SQL in parameters
- **Mitigation:**
  - Input validation and sanitization
  - Parameterized queries (SQLAlchemy)
  - URL format validation

#### A3: Rate Limit Bypass
- **Vector:** Multiple IPs, request flooding
- **Mitigation:**
  - Rate limiting middleware (TODO)
  - IP-based throttling
  - Request queuing

### 5.2 Frontend Attacks

#### A4: Cross-Site Scripting (XSS)
- **Vector:** Injected scripts in target names, reports
- **Mitigation:**
  - React's automatic escaping
  - Content-Security-Policy headers
  - Input sanitization

#### A5: Cross-Site Request Forgery (CSRF)
- **Vector:** Forced actions from authenticated user
- **Mitigation:**
  - CSRF tokens (TODO)
  - SameSite cookie attributes
  - Origin header validation

#### A6: Session Hijacking
- **Vector:** Stolen session tokens
- **Mitigation:**
  - Secure cookie flags
  - Token expiration
  - HTTPS enforcement

### 5.3 Database Attacks

#### A7: SQLite File Access
- **Vector:** Direct file read, path traversal
- **Mitigation:**
  - Restrictive file permissions (600)
  - Store outside web root
  - Database encryption (TODO)

#### A8: Data Leakage via Errors
- **Vector:** Detailed error messages
- **Mitigation:**
  - Generic error responses
  - Error logging (not display)
  - Exception handling

### 5.4 Reconnaissance Engine Attacks

#### A9: SSRF (Server-Side Request Forgery)
- **Vector:** Manipulated target URLs accessing internal resources
- **Mitigation:**
  - URL allowlist/blocklist
  - Block private IP ranges (configurable)
  - Request destination validation

#### A10: Resource Exhaustion
- **Vector:** Scanning large targets, deep recursion
- **Mitigation:**
  - Maximum depth limits
  - Timeout enforcement
  - Memory limits

#### A11: Response Payload Attacks
- **Vector:** Malicious content in target responses
- **Mitigation:**
  - Response size limits
  - Content-type validation
  - Safe parsing libraries

## 6. Mitigations Summary

### 6.1 Implemented Mitigations

| Control | Status | Description |
|---------|--------|-------------|
| Input Validation | ✅ | Pydantic schemas validate all inputs |
| Parameterized Queries | ✅ | SQLAlchemy ORM prevents SQL injection |
| XSS Prevention | ✅ | React escapes output by default |
| Rate Limiting | ✅ | Configurable delays between requests |
| Timeout Controls | ✅ | Request timeouts prevent hanging |
| Error Handling | ✅ | Generic errors to clients |

### 6.2 Recommended Enhancements

| Control | Priority | Effort | Description |
|---------|----------|--------|-------------|
| Authentication | HIGH | Medium | Add JWT/OAuth2 middleware |
| HTTPS Enforcement | HIGH | Low | TLS termination at proxy |
| Audit Logging | MEDIUM | Low | Log all user actions |
| Role-Based Access | MEDIUM | Medium | Separate admin/operator roles |
| Database Encryption | MEDIUM | High | Encrypt SQLite at rest |
| CSP Headers | LOW | Low | Content-Security-Policy |
| CSRF Tokens | LOW | Medium | Token validation on mutations |

## 7. Secure Deployment Checklist

### Development Environment
- [ ] Run on isolated network
- [ ] Use test targets only
- [ ] Disable external access
- [ ] Review logs regularly

### Production Environment
- [ ] Enable authentication
- [ ] Configure HTTPS
- [ ] Set restrictive firewall rules
- [ ] Enable audit logging
- [ ] Configure backup procedures
- [ ] Set up monitoring/alerting
- [ ] Document incident response
- [ ] Train operators on security

### Scanning Operations
- [ ] Verify authorization documentation
- [ ] Configure appropriate rate limits
- [ ] Define scope boundaries
- [ ] Establish communication channels
- [ ] Plan for emergency stop

## 8. Risk Matrix

```
Impact
  HIGH    │ T05    T06    T07    │ T09    T10
          │                       │
 MEDIUM   │        T01    T04    │ T02    T08
          │                       │
  LOW     │ T03                   │
          └───────────────────────┘
            LOW    MEDIUM   HIGH
                Likelihood
```

## 9. Incident Response

### Detection Indicators

| Indicator | Possible Cause | Response |
|-----------|----------------|----------|
| Unusual API traffic | Attack attempt | Review logs, rate limit |
| Failed auth attempts | Brute force | Block IP, alert |
| Unexpected exports | Data theft | Audit trail review |
| Scanner crashes | Malicious target | Isolate, investigate |

### Response Procedures

1. **Containment:** Stop affected scans, isolate systems
2. **Assessment:** Determine scope and impact
3. **Eradication:** Remove threat, patch vulnerabilities
4. **Recovery:** Restore from backup if needed
5. **Lessons:** Update threat model, improve controls

## 10. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-01 | Initial threat model |
