# BlackBox Recon Architecture

## High-Level Design

BlackBox Recon follows a modular, phased architecture separating concerns between the reconnaissance engine, API layer, database, and frontend UI.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Targets  │ │  Scans   │ │ Reports  │ │ Attack Surface   │   │
│  │  Manager │ │  Viewer  │ │  Export  │ │     Graph        │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP/REST API
┌─────────────────────────────────────────────────────────────────┐
│                      Backend (FastAPI)                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    API Routers                           │   │
│  │  /api/targets  /api/scans  /api/reports  /api/graph      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Recon Engine                            │   │
│  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐       │   │
│  │  │DNS  │ │HTTP │ │Tech │ │ JS  │ │Param│ │Sec  │       │   │
│  │  │Disc │ │Fing │ │Det  │ │Anal │ │Disc │ │Hdr  │       │   │
│  │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘       │   │
│  │  ┌─────┐ ┌─────┐ ┌─────┐                                │   │
│  │  │ API │ │Vuln │ │Graph│                                │   │
│  │  │Disc │ │Class│ │Build│                                │   │
│  │  └─────┘ └─────┘ └─────┘                                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 Database (SQLite)                        │   │
│  │  Targets │ Scans │ ScanEvents │ Findings │ GraphNodes   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Frontend (React + Vite + TypeScript)

**Location:** `ui/src/`

- **Components:** Reusable UI elements (TargetsList, ScanView, ReportView, AttackSurfaceGraph)
- **Hooks:** Custom React hooks for API interaction
- **Types:** TypeScript interfaces for API responses
- **Styling:** Tailwind CSS for modern, responsive design

### 2. Backend API (FastAPI)

**Location:** `app/api/`

| Router | Endpoints | Description |
|--------|-----------|-------------|
| targets | GET/POST/PUT/DELETE `/api/targets` | Target CRUD operations |
| scans | GET/POST `/api/scans`, POST `/api/scans/{id}/start` | Scan management |
| reports | GET `/api/reports/{id}`, `/api/reports/{id}/export/{format}` | Report generation |
| graph | GET `/api/graph/{scan_id}` | Attack surface graph data |

### 3. Reconnaissance Engine

**Location:** `app/recon/`

Modular phase-based architecture. Each phase is independent and can be extended:

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `dns_discovery.py` | DNS enumeration, subdomain discovery |
| 2 | `http_fingerprinting.py` | HTTP methods, status codes, redirects |
| 3 | `tech_detection.py` | Technology stack identification (Wappalyzer-style) |
| 4 | `js_analysis.py` | JavaScript file analysis, endpoint extraction |
| 5 | `param_discovery.py` | URL parameter and form field discovery |
| 6 | `security_headers.py` | Security header analysis |
| 7 | `api_discovery.py` | REST/GraphQL API endpoint detection |
| 8 | `vuln_classification.py` | Potential vulnerability identification |
| 9 | `graph_builder.py` | NetworkX-based attack surface graph construction |

### 4. Database Layer

**Location:** `app/db.py`, `app/models.py`

**Tables:**

- `targets`: Target information (url, name, notes)
- `scans`: Scan metadata (target_id, status, started_at, completed_at)
- `scan_events`: Per-phase results linked to scans
- `findings`: Individual security findings
- `graph_nodes`: Attack surface graph nodes and edges

## Data Flow

### Scan Execution Flow

```
1. User creates target via UI
2. User initiates scan
3. API creates Scan record with status="running"
4. ReconEngine starts pipeline:
   For each phase:
     a. Execute phase logic
     b. Store results in ScanEvent
     c. Update progress
     d. Check for stop signal
5. Build attack surface graph
6. Generate report summary
7. Update Scan status="completed"
8. UI polls for status updates
```

### Report Generation Flow

```
1. Request GET /api/reports/{id}/export/json
2. Load Scan and related ScanEvents
3. Aggregate findings by category
4. Build graph structure
5. Format based on export type:
   - JSON: Raw structured data
   - Markdown: Human-readable text
   - HTML: Styled document
6. Return formatted response
```

## Phase Breakdown

### Phase 1: UI + Project Structure
- Basic React app setup
- Component scaffolding
- API integration foundation

### Phase 2: Target Management
- Target CRUD API
- Target list/form components
- Validation and error handling

### Phase 3: Reconnaissance Engine
- Base recon phase class
- Pipeline orchestration
- Detection evasion stubs

### Phase 4: HTTP Fingerprinting
- HTTP method detection
- Status code analysis
- Redirect following

### Phase 5: Endpoint Discovery
- Link extraction
- robots.txt parsing
- sitemap.xml parsing

### Phase 6: Vulnerability Checks
- Pattern-based detection
- Risk classification
- False positive reduction

### Phase 7: Event Database
- SQLAlchemy models
- Async session management
- Event storage/retrieval

### Phase 8: Attack Graph
- NetworkX integration
- Node/edge creation
- JSON serialization

### Phase 9: Reporting
- Summary statistics
- Multi-format export
- Template rendering

### Phase 10: Tests + Docker
- Pytest coverage
- Docker configuration
- CI/CD readiness

## Frontend/Backend Interaction

### API Communication Pattern

```typescript
// Frontend hook example
const useScan = (scanId: number) => {
  const [scan, setScan] = useState<Scan | null>(null);
  
  useEffect(() => {
    const fetchScan = async () => {
      const response = await fetch(`/api/scans/${scanId}`);
      const data = await response.json();
      setScan(data);
    };
    
    fetchScan();
    const interval = setInterval(fetchScan, 2000); // Poll every 2s
    return () => clearInterval(interval);
  }, [scanId]);
  
  return scan;
};
```

### WebSocket Support (Future)

For real-time updates without polling, WebSocket support can be added:

```python
@app.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    # Stream scan events as they occur
```

## Configuration

Configuration is managed via environment variables and `app/config.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | sqlite+aiosqlite:///./blackbox.db | Database connection |
| DEFAULT_USER_AGENT | BlackBoxRecon/1.0 | Default HTTP User-Agent |
| REQUEST_DELAY | 0.5 | Delay between requests (seconds) |
| PROXY_URL | None | Optional proxy for requests |
| MAX_CONCURRENT | 5 | Maximum concurrent requests |

## Extensibility

### Adding New Recon Phases

1. Create new module in `app/recon/`
2. Inherit from `BaseReconPhase`
3. Implement `execute()` method
4. Register in `app/recon/pipeline.py`

### Adding New Export Formats

1. Add formatter in `app/services/exporters.py`
2. Register format in report router
3. Add UI button for new format

### Adding New Detection Patterns

1. Update pattern files in `app/recon/patterns/`
2. Patterns use YAML/JSON for easy maintenance
3. Reload patterns without restart (future feature)
