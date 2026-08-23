# BlackBox Recon – Autonomous Attack Surface Mapper

## Overview

BlackBox Recon is a comprehensive security reconnaissance tool that automatically maps the attack surface of target systems. It performs multi-phase analysis including DNS discovery, HTTP fingerprinting, technology detection, JavaScript analysis, parameter discovery, security header analysis, API discovery, and vulnerability classification.

## Features

- **Multi-Phase Reconnaissance**: 9-phase automated pipeline
- **Interactive UI**: Modern React-based web interface
- **Attack Surface Graph**: Visual tree representation of discovered endpoints
- **Detailed Reporting**: JSON, Markdown, and HTML export options
- **Target Management**: CRUD operations for scan targets
- **Live Scan Status**: Real-time progress tracking per phase
- **Detection Evasion**: Configurable User-Agent, delays, and proxy support
- **Event Database**: SQLite-backed storage for all scan results

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker (optional)

### Running with Docker

```bash
docker-compose up --build
```

Access the UI at `http://localhost:3000` and API at `http://localhost:8000`.

### Manual Setup

#### Backend

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0
```

#### Frontend

```bash
cd ui
npm install
npm run dev
```

## Usage Examples

### Adding a Target via UI

1. Navigate to "Targets" in the sidebar
2. Click "Add Target"
3. Enter URL or IP (e.g., `lab.local`)
4. Save

### Running a Scan

1. Go to "Scans" section
2. Select a target
3. Click "Start Scan"
4. Watch live progress through phases

### Viewing Reports

1. Navigate to completed scan
2. View summary cards with counts
3. Expand per-phase findings
4. Export as JSON/Markdown/HTML

### API Usage

```bash
# Create target
curl -X POST http://localhost:8000/api/targets \
  -H "Content-Type: application/json" \
  -d '{"url": "lab.local", "name": "Lab Environment"}'

# Start scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1}'

# Get report
curl http://localhost:8000/api/reports/1/export/json
```

## Project Structure

```
blackbox-recon/
├── app/                    # Backend (FastAPI)
│   ├── api/               # API routers
│   ├── recon/             # Reconnaissance engine
│   ├── main.py           # Application entry
│   ├── config.py         # Configuration
│   ├── db.py             # Database setup
│   ├── models.py         # SQLAlchemy models
│   └── schemas.py        # Pydantic schemas
├── ui/                    # Frontend (React + Vite)
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom hooks
│   │   ├── types/        # TypeScript types
│   │   └── App.tsx       # Main component
│   └── package.json
├── tests/                 # Pytest tests
├── docs/                  # Documentation
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
├── THREAT_MODEL.md
├── CHANGELOG.md
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## License

MIT License - For educational and authorized security testing only.

## Disclaimer

This tool is intended for legitimate security research and authorized penetration testing only. Always obtain proper authorization before scanning any system you do not own.
