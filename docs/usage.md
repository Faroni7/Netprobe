# BlackBox Recon Usage Guide

## Running Scans

### Via UI

1. **Add a Target**
   - Navigate to "Targets" in the sidebar
   - Click "Add Target"
   - Enter target name and URL/IP
   - Save

2. **Start a Scan**
   - Go to "Scans" section
   - Find your target's scan or create one
   - Click the Play button to start
   - Monitor progress in real-time

3. **View Results**
   - Click on completed scan
   - View phase-by-phase results
   - Access full report via Report icon

### Via API

```bash
# Create target
curl -X POST http://localhost:8000/api/targets \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab", "url": "lab.local"}'

# Create scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1}'

# Start scan
curl -X POST http://localhost:8000/api/scans/1/start

# Check status
curl http://localhost:8000/api/scans/1
```

## Interpreting Reports

### Summary Metrics

| Metric | Description |
|--------|-------------|
| Endpoints | Discovered URLs/paths |
| API Routes | REST/GraphQL endpoints |
| Auth Mechanisms | Login/auth systems found |
| Debug Interfaces | Admin/debug panels |
| Suspicious Params | Potentially dangerous parameters |
| Possible Vulns | High-severity findings |
| Missing Controls | Security header issues |

### Phase Results

Each reconnaissance phase produces specific data:

1. **DNS Discovery**: Subdomains, DNS records
2. **HTTP Fingerprinting**: Methods, status codes
3. **Tech Detection**: Frameworks, servers
4. **JS Analysis**: Extracted endpoints from scripts
5. **Param Discovery**: URL/form parameters
6. **Security Headers**: Missing/present headers
7. **API Discovery**: OpenAPI/Swagger docs
8. **Vuln Classification**: Pattern matches
9. **Graph Builder**: Attack surface tree

## Exporting Data

### JSON Export

```bash
curl http://localhost:8000/api/reports/1/export/json \
  -o report.json
```

### Markdown Export

```bash
curl http://localhost:8000/api/reports/1/export/markdown \
  -o report.md
```

### HTML Export

```bash
curl http://localhost:8000/api/reports/1/export/html \
  -o report.html
```

## Using the Attack Surface Graph

The graph visualization shows:

- **Root node**: Target domain/IP
- **Endpoint nodes**: Discovered paths
- **API nodes**: API routes
- **Parameter nodes**: Input vectors

Click nodes to expand/collapse branches.

## Configuration

Edit environment variables or `.env` file:

```bash
REQUEST_DELAY=0.5      # Seconds between requests
MAX_CONCURRENT=5       # Parallel requests
DEFAULT_USER_AGENT=... # HTTP User-Agent
PROXY_URL=http://...   # Optional proxy
```

## Best Practices

1. **Always obtain authorization** before scanning
2. **Start with low concurrency** for fragile targets
3. **Review findings manually** - automated tools have false positives
4. **Export reports** for documentation
5. **Clean up test data** after engagements
