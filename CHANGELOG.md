# Changelog

All notable changes to BlackBox Recon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.1] - 2026-08-23

### Fixed
- **Scan Events API**: Added missing `/api/scans/{scan_id}/events` endpoint for retrieving scan events (P1)
- **Frontend dependency**: Replaced deprecated `react-flow-renderer` with `@xyflow/react` v12 (P1)
- **TypeScript build error**: Removed unused `refetch` variable in ScansList component (P3)

### Verified
- Full end-to-end scan lifecycle: target creation → scan execution → 9-phase pipeline → report generation
- All export formats working: JSON, Markdown, HTML
- Frontend production build succeeds
- All existing tests pass (10/10)

## [v0.1.0] - 2024-01-01

### Added

#### Core Features
- Initial release of BlackBox Recon
- Multi-phase reconnaissance pipeline (9 phases)
- Target management (CRUD operations)
- Scan management with live status tracking
- Attack surface graph visualization
- Report generation with multiple export formats (JSON, Markdown, HTML)

#### Backend (FastAPI)
- RESTful API for targets, scans, reports, and graph data
- Async SQLAlchemy database layer with SQLite
- Modular recon engine with phase-based architecture
- Detection evasion capabilities (User-Agent, delays, proxy)
- Pydantic schemas for request/response validation

#### Reconnaissance Phases
1. DNS Discovery - Subdomain enumeration
2. HTTP Fingerprinting - Method detection, status codes
3. Technology Detection - Stack identification
4. JavaScript Analysis - Endpoint extraction from JS files
5. Parameter Discovery - URL and form parameter detection
6. Security Header Analysis - Missing security headers
7. API Discovery - REST/GraphQL endpoint detection
8. Vulnerability Classification - Pattern-based detection
9. Graph Builder - NetworkX-based attack surface construction

#### Frontend (React + Vite)
- Modern, responsive UI with Tailwind CSS
- Target management interface
- Scan viewer with real-time progress
- Interactive attack surface graph/tree
- Detailed report view with expandable sections
- Export functionality (JSON, Markdown, HTML)
- Dark/light theme support
- Toast notifications for user feedback

#### Database
- SQLite backend with async support
- Models: Target, Scan, ScanEvent, Finding, GraphNode
- Event storage for per-phase results

#### Documentation
- README.md - Overview and quickstart
- ARCHITECTURE.md - System design and data flow
- SECURITY.md - Security guidelines and best practices
- THREAT_MODEL.md - Comprehensive threat analysis
- docs/usage.md - How to run scans and interpret results
- docs/api.md - API endpoint reference

#### Infrastructure
- Dockerfile for containerized deployment
- docker-compose.yml for single-command setup
- requirements.txt for Python dependencies
- package.json for frontend dependencies
- Basic pytest test suite

### Technical Details

**Backend Stack:**
- Python 3.11+
- FastAPI 0.109+
- SQLAlchemy 2.0+ (async)
- Pydantic 2.0+
- NetworkX 3.0+
- aiohttp for async HTTP
- uvicorn as ASGI server

**Frontend Stack:**
- React 18+
- TypeScript 5+
- Vite 5+
- Tailwind CSS 3+
- React Flow for graph visualization
- Axios for API calls

**Development Tools:**
- pytest for backend testing
- ESLint/Prettier for frontend linting
- Docker for containerization

### Known Issues
- WebSocket support for real-time updates not yet implemented
- Authentication middleware pending (planned for v0.2.0)
- Rate limiting by IP address not yet implemented

### TODO (Future Versions)
- JWT/OAuth2 authentication
- WebSocket real-time scan updates
- Advanced rate limiting
- Role-based access control
- Database encryption at rest
- CI/CD pipeline integration
- Additional recon phases (subdomain brute-forcing, port scanning)
- Plugin system for custom phases

[v0.1.0]: https://github.com/blackboxrecon/blackbox-recon/releases/tag/v0.1.0
