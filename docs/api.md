# BlackBox Recon API Reference

## Base URL

```
http://localhost:8000/api
```

## Endpoints

### Targets

#### GET /targets
List all targets.

**Response:** `Target[]`

#### POST /targets
Create a new target.

**Body:**
```json
{
  "name": "string",
  "url": "string",
  "notes": "string (optional)"
}
```

**Response:** `Target`

#### GET /targets/{id}
Get a specific target.

**Response:** `Target`

#### PUT /targets/{id}
Update a target.

**Body:** Partial `Target` object

**Response:** `Target`

#### DELETE /targets/{id}
Delete a target.

**Response:** `204 No Content`

### Scans

#### GET /scans
List all scans.

**Response:** `Scan[]`

#### POST /scans
Create a new scan.

**Body:**
```json
{
  "target_id": number
}
```

**Response:** `Scan`

#### GET /scans/{id}
Get scan status.

**Response:** `Scan`

#### POST /scans/{id}/start
Start a scan execution.

**Response:** `Scan`

#### POST /scans/{id}/stop
Stop a running scan.

**Response:** `Scan`

### Reports

#### GET /reports/{id}
Get full report.

**Response:** `FullReport`

#### GET /reports/{id}/export/json
Export as JSON.

**Response:** JSON file download

#### GET /reports/{id}/export/markdown
Export as Markdown.

**Response:** MD file download

#### GET /reports/{id}/export/html
Export as HTML.

**Response:** HTML file download

## Data Models

### Target
```typescript
{
  id: number
  name: string
  url: string
  notes: string | null
  is_active: boolean
  created_at: datetime
  updated_at: datetime | null
}
```

### Scan
```typescript
{
  id: number
  target_id: number
  status: "pending" | "running" | "completed" | "failed" | "stopped"
  progress: number (0-100)
  current_phase: string | null
  started_at: datetime | null
  completed_at: datetime | null
  error_message: string | null
  created_at: datetime
}
```

### FullReport
```typescript
{
  scan_id: number
  target_name: string
  target_url: string
  status: string
  summary: {
    total_endpoints: number
    api_routes: number
    authentication_mechanisms: number
    debug_interfaces: number
    suspicious_parameters: number
    possible_vulns: number
    missing_controls: number
  }
  phases: Array<{
    phase_name: string
    phase_order: number
    status: string
    findings_count: number
    data: object | null
  }>
  endpoints: string[]
  graph_tree: object | null
  created_at: datetime
  completed_at: datetime | null
}
```
