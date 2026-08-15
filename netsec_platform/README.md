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
git clone https://github.com/Faroni7/Netprobe.git
cd Netprobe/netsec_platform
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd frontend && npm install && cd ..
pytest --cov=src
uvicorn src.netsec_platform.api.main:app --host 127.0.0.1 --port 8000
```

## Deployment

### Cross-Platform Compatibility

✅ **Fully compatible** with Linux, macOS, and Windows (WSL2 recommended for Windows).

---

### 🐧 Linux (Ubuntu/Debian)

#### Step 1: Install System Dependencies

```bash
sudo apt update
sudo apt install -y python3.10 python3.10-venv python3-pip \
                    libpcap-dev tcpdump git curl nodejs npm \
                    build-essential libssl-dev
```

#### Step 2: Clone and Setup Backend

```bash
git clone https://github.com/Faroni7/Netprobe.git
cd Netprobe/netsec_platform
python3.10 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[prod]"
```

#### Step 3: Setup Frontend

```bash
cd frontend
npm install
npm run build
cd ..
```

#### Step 4: Create Data Directories

```bash
sudo mkdir -p /var/netsec_platform/{data,logs}
sudo chown -R $USER:$USER /var/netsec_platform
```

#### Step 5: Initialize Database

```bash
python -m src.netsec_platform.database.init_db
```

#### Step 6: Configure Platform

Create `/etc/netsec_platform/config.yaml`:

```yaml
capture:
  profile: standard  # metadata-only, standard, full-evidence
  interface: eth0    # or wlan0, vmnet1, etc.
  max_storage_gb: 100
  retention_days: 7

storage:
  encrypt_evidence: true
  evidence_path: /var/netsec_platform/data/evidence
  pcap_path: /var/netsec_platform/data/pcap

ess:
  enabled: true
  require_confirmation: true

kubernetes:
  enabled: false
  kubeconfig: ~/.kube/config

cloud:
  enabled: false
  providers: []
```

#### Step 7: Start Platform (Development)

```bash
# Terminal 1: Backend API
source .venv/bin/activate
uvicorn src.netsec_platform.api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload

# Terminal 2: Frontend (dev mode)
cd frontend
npm run dev
```

Access:
- Web UI: `http://localhost:5173`
- API Docs: `http://localhost:8000/docs`
- Default credentials: `admin` / `ChangeMe123!`

#### Step 8: Start Platform (Production with systemd)

Create `/etc/systemd/system/netsec-api.service`:

```ini
[Unit]
Description=NetSec Platform API
After=network.target

[Service]
Type=simple
User=netsec
Group=netsec
WorkingDirectory=/opt/netsec-platform
Environment="PATH=/opt/netsec-platform/.venv/bin"
ExecStart=/opt/netsec-platform/.venv/bin/uvicorn src.netsec_platform.api.main:app \
  --host 127.0.0.1 \
  --port 8000 \
  --workers 4
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/netsec-frontend.service`:

```ini
[Unit]
Description=NetSec Platform Frontend
After=network.target netsec-api.service

[Service]
Type=simple
User=netsec
Group=netsec
WorkingDirectory=/opt/netsec-platform/frontend
ExecStart=/usr/bin/npm run start:prod
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start services:

```bash
sudo useradd -r -s /bin/false netsec
sudo systemctl daemon-reload
sudo systemctl enable netsec-api netsec-frontend
sudo systemctl start netsec-api netsec-frontend
sudo systemctl status netsec-api netsec-frontend
```

#### Step 9: Configure Nginx Reverse Proxy (Optional)

```nginx
server {
    listen 443 ssl;
    server_name netsec.example.com;

    ssl_certificate /etc/ssl/certs/netsec.crt;
    ssl_certificate_key /etc/ssl/private/netsec.key;

    location / {
        proxy_pass http://localhost:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

### 🍎 macOS

#### Step 1: Install Dependencies via Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.10 libpcap node git openssl
```

#### Step 2: Clone and Setup

```bash
git clone https://github.com/Faroni7/Netprobe.git
cd Netprobe/netsec_platform
python3.10 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[prod]"
```

#### Step 3: Setup Frontend

```bash
cd frontend
npm install
npm run build
cd ..
```

#### Step 4: Create Data Directories

```bash
mkdir -p ~/netsec_platform/{data,logs}
export NETSEC_DATA_PATH=~/netsec_platform/data
export NETSEC_LOG_PATH=~/netsec_platform/logs
```

#### Step 5: Initialize and Configure

```bash
python -m src.netsec_platform.database.init_db
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

#### Step 6: Start Platform

```bash
# Development mode
uvicorn src.netsec_platform.api.main:app --host 127.0.0.1 --port 8000 &
cd frontend && npm run dev
```

**Note**: Packet capture on macOS requires additional permissions. You may need to:
1. Grant terminal access in System Preferences → Security & Privacy → Privacy → Accessibility
2. Use `sudo` for live capture: `sudo -E $(which python) -m src.netsec_platform.capture.start`

---

### 🪟 Windows (WSL2 Recommended)

#### Option A: WSL2 (Recommended)

1. **Install WSL2**:
```powershell
wsl --install -d Ubuntu-22.04
```

2. **Inside WSL2**, follow the [Linux deployment steps](#-linux-ubuntudebian) above.

3. **Access network interfaces**: WSL2 can access Windows network interfaces through `/mnt/c/` and mirrored networking (Windows 11).

#### Option B: Native Windows (Limited Support)

⚠️ **Limitations**: Some features may not work correctly on native Windows due to libpcap compatibility.

```powershell
# Install Python 3.10+ from python.org
# Install Node.js from nodejs.org
# Install Npcap from https://nmap.org/npcap/

git clone https://github.com/Faroni7/Netprobe.git
cd Netprobe/netsec_platform
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[prod]"

cd frontend
npm install
npm run build
cd ..

python -m src.netsec_platform.database.init_db
uvicorn src.netsec_platform.api.main:app --host 127.0.0.1 --port 8000
```

---

### ☁️ Cloud Deployment (AWS/Azure/GCP)

#### AWS EC2 Example

```bash
# Launch Ubuntu 22.04 instance
# Security Group: Allow 443 (HTTPS), 22 (SSH)

ssh ubuntu@your-instance-ip

# Install dependencies
sudo apt update && sudo apt install -y python3.10 python3-pip libpcap-dev nodejs npm

# Clone and setup
git clone https://github.com/Faroni7/Netprobe.git
cd Netprobe/netsec_platform
python3.10 -m venv .venv
source .venv/bin/activate
pip install -e ".[prod]"

# Configure for cloud
cat > config.yaml << EOF
capture:
  profile: standard
  interface: eth0
  
cloud:
  enabled: true
  providers:
    - aws
    
storage:
  encrypt_evidence: true
  use_s3: true
  s3_bucket: netsec-evidence-bucket
EOF

# Deploy with systemd (see Linux section)
```

**Important**: Cloud VPC Flow Logs integration requires IAM roles with appropriate permissions. See `docs/CLOUD_DEPLOYMENT.md` for detailed configuration.

---

### 🐳 Docker Deployment (Coming Soon)

Docker Compose configuration is under development. Expected usage:

```bash
docker-compose up -d
# Access at http://localhost:8000
```

---

## Post-Deployment Steps

### 1. Change Default Credentials

```bash
curl -X POST http://localhost:8000/api/v1/auth/change-password \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"old_password": "ChangeMe123!", "new_password": "YourSecurePassword!"}'
```

### 2. Enable ESS Test

Verify Emergency Security Stop works:

```bash
curl -X POST http://localhost:8000/api/v1/ess/activate \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -d '{"reason": "ESS functionality test"}'
```

Expected response time: **<100ms**

### 3. Configure Capture Interface

Select your network interface:

```bash
# List available interfaces
python -m src.netsec_platform.capture.discover_interfaces

# Update config.yaml with chosen interface
# interface: eth0  # or wlan0, vmnet1, vboxnet0, etc.
```

### 4. Enable Encryption

For production, ensure encryption is enabled:

```yaml
storage:
  encrypt_evidence: true
  encryption_key_source: env  # or: aws-kms, azure-keyvault, gcp-kms
```

Set environment variable:
```bash
export NETSEC_ENCRYPTION_KEY=<your-32-byte-key>
```

### 5. Setup Monitoring

Configure log rotation in `/etc/logrotate.d/netsec`:

```
/var/netsec_platform/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 netsec netsec
}
```

---

## Troubleshooting

### Cannot capture packets (Permission denied)

**Linux**: Add user to netdev group or use capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/python
# OR
sudo usermod -aG netdev $USER
```

**macOS**: Grant terminal accessibility permissions in System Preferences.

**Windows**: Run as Administrator or install Npcap with WinPcap compatibility mode.

### Frontend won't build

```bash
cd frontend
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
npm run build
```

### Database initialization fails

```bash
rm /var/netsec_platform/data/netsec.db
python -m src.netsec_platform.database.init_db
```

### ESS not responding

Check if service is running:
```bash
systemctl status netsec-api
journalctl -u netsec-api -f
```

### High memory usage

Reduce capture buffer size in config:
```yaml
capture:
  max_buffer_mb: 512  # Default: 1024
  worker_threads: 2   # Default: 4
```

### Cloud/Kubernetes integration not working

Verify credentials and permissions:
```bash
# AWS
aws sts get-caller-identity

# Kubernetes
kubectl auth can-i list pods

# Azure
az account show

# GCP
gcloud config list
```

See `docs/TROUBLESHOOTING.md` for more detailed guidance.

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
