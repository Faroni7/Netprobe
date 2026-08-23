# Security Guidelines

## Responsible Use

BlackBox Recon is a powerful security tool designed for **authorized security testing only**. 

### Legal Warning

⚠️ **ALWAYS obtain written authorization before scanning any system you do not own.**

Unauthorized scanning may:
- Violate computer crime laws (CFAA, Computer Misuse Act, etc.)
- Breach terms of service
- Cause service disruption
- Result in legal action

### Authorized Use Cases

✅ You own the target system
✅ You have explicit written permission from the owner
✅ You are conducting authorized penetration testing
✅ You are performing security research in an isolated lab environment

## Safe Defaults

BlackBox Recon includes several safety features by default:

| Feature | Default | Purpose |
|---------|---------|---------|
| Rate Limiting | 0.5s delay | Prevent DoS |
| Concurrent Requests | 5 max | Reduce load |
| Timeout | 10s | Prevent hanging |
| User-Agent | Identifiable | Transparency |

## Rate Limiting

Built-in rate limiting prevents overwhelming targets:

```python
# Configurable in app/config.py
REQUEST_DELAY = 0.5  # seconds between requests
MAX_CONCURRENT = 5   # maximum parallel requests
```

**Recommendations:**
- Increase delay for production systems (2-5 seconds)
- Reduce concurrent requests for fragile services
- Respect robots.txt directives
- Implement exponential backoff on errors

## Authentication Considerations

### API Security

The FastAPI backend should be secured in production:

1. **Enable authentication** - Add JWT/OAuth2 middleware
2. **Use HTTPS** - Never expose over plain HTTP
3. **Rate limit API** - Prevent abuse
4. **Validate input** - All user input is sanitized

### UI Security

The React frontend includes:

- Input validation on forms
- XSS prevention via React's escaping
- CORS configuration for API access

**Production hardening:**
```bash
# Enable authentication middleware
# Configure secure cookies
# Set Content-Security-Policy headers
# Enable HSTS
```

## Detection Evasion

BlackBox Recon includes basic evasion capabilities for authorized red team operations:

| Feature | Description |
|---------|-------------|
| Custom User-Agent | Rotate or spoof browser signatures |
| Request Delays | Randomize timing patterns |
| Proxy Support | Route through TOR or commercial proxies |

⚠️ **Use evasion techniques ONLY in authorized engagements.**

## Data Protection

### Stored Data

Scan results may contain sensitive information:

- Discovered endpoints
- Technology stack details
- Potential vulnerabilities
- Network topology

**Protect stored data:**
- Encrypt database at rest
- Restrict file permissions
- Implement access controls
- Regular data purging

### Export Security

Reports contain sensitive findings:

- Password-protect exported files
- Use secure transfer methods
- Delete after use
- Audit export actions

## Infrastructure Security

### Docker Deployment

When running with Docker:

```yaml
# docker-compose.yml security settings
security_opt:
  - no-new-privileges:true
read_only: true  # Where possible
cap_drop:
  - ALL
```

### Network Isolation

Run scans from isolated networks:
- Separate VLAN for security tools
- No direct internet access
- Outbound proxy for controlled access

## Incident Response

If accidental unauthorized scanning occurs:

1. **Stop immediately** - Cancel all running scans
2. **Document** - Record what was scanned and when
3. **Preserve logs** - For investigation
4. **Notify** - Inform security/legal teams
5. **Cooperate** - With any affected parties

## Vulnerability Disclosure

If you discover vulnerabilities in BlackBox Recon itself:

1. Email: security@blackboxrecon.example
2. Include: Version, steps to reproduce, impact
3. Allow: 90 days for patch development

## Compliance Considerations

| Regulation | Relevance |
|------------|-----------|
| GDPR | Personal data in scan results |
| PCI-DSS | Scanning cardholder environments |
| HIPAA | Healthcare system testing |
| SOX | Financial system assessments |

Always consult legal counsel for compliance requirements.

## Logging and Auditing

Enable comprehensive logging for accountability:

```python
# app/config.py
LOG_LEVEL = "INFO"
LOG_FILE = "/var/log/blackbox_recon.log"
AUDIT_EXPORTS = True
```

**Log contents:**
- User actions
- Scan initiation/completion
- Export events
- Authentication attempts

## Updates and Patches

Keep BlackBox Recon updated:

```bash
git pull origin main
pip install -r requirements.txt --upgrade
npm install  # For frontend
```

Subscribe to security advisories for dependency updates.
