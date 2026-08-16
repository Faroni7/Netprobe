# Report Export Feature Guide

## Overview

The NetSec Platform now includes comprehensive report export functionality, allowing analysts to generate and download security reports in multiple formats for sharing, archiving, and compliance purposes.

## Supported Export Formats

| Format | Extension | Use Case | Dependencies |
|--------|-----------|----------|--------------|
| **HTML** | `.html` | Interactive web reports with charts | None |
| **PDF** | `.pdf` | Printable documents, official submissions | `weasyprint` (optional) |
| **JSON** | `.json` | Machine-readable, API integration | None |
| **CSV** | `.csv` | Spreadsheet analysis, Excel import | None |
| **Markdown** | `.md` | Documentation, GitHub wikis, plain text | None |
| **DOCX** | `.docx` | Word documents (via HTML conversion) | `python-docx` (optional) |

## Usage Examples

### Basic Export

```python
from netsec_platform.reporting import ReportGenerator
from netsec_platform.storage.database import DatabaseManager

# Initialize
db = DatabaseManager()
reporter = ReportGenerator(db)

# Export a standard HTML report
result = reporter.export_report(
    format='html',
    title="Q4 Security Assessment",
    analyst="John Doe"
)

print(f"Report saved to: {result['filepath']}")
print(f"File size: {result['size_bytes']} bytes")
```

### Export Multiple Formats Simultaneously

```python
# Generate the same report in 4 formats at once
results = reporter.export_multiple_reports(
    formats=['html', 'json', 'csv', 'md'],
    report_type='standard',
    case_id='CASE-2024-001',
    title="Incident Response Report",
    analyst="Security Team"
)

print(f"Generated {results['total_files']} files")
print(f"Total size: {results['total_size_bytes']} bytes")
print(f"Export directory: {results['export_dir']}")

for export in results['exports']:
    if export.get('success'):
        print(f"  ✓ {export['filename']} ({export['size_bytes']} bytes)")
    else:
        print(f"  ✗ {export['format']}: {export.get('error')}")
```

### Filter by Case and Time Range

```python
from datetime import datetime, timedelta

# Define time range (last 30 days)
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=30)

# Export restricted report for specific case
result = reporter.export_report(
    report_type='restricted',
    format='pdf',
    case_id='CASE-2024-001',
    time_range_start=start_date,
    time_range_end=end_date,
    include_findings=True,
    include_evidence=True,  # Only included in restricted reports
    include_timeline=True,
    title="Detailed Investigation Report",
    analyst="Lead Investigator"
)
```

### Custom Filename

```python
result = reporter.export_report(
    format='html',
    filename='executive_summary_2024_q4.html',
    title="Executive Summary Q4 2024"
)
```

### View Export History

```python
# Get last 50 exported reports
history = reporter.get_export_history(limit=50)

for report in history:
    print(f"{report['filename']}")
    print(f"  Created: {report['created_at']}")
    print(f"  Size: {report['size_bytes']} bytes")
    print(f"  Format: {report['format']}")
    print()
```

### Cleanup Old Exports

```python
# Delete exports older than 30 days
deleted_count = reporter.cleanup_old_exports(days=30)
print(f"Deleted {deleted_count} old export files")
```

## Configuration

### Export Directory

By default, exports are saved to `./exports` relative to the working directory.

To customize:

```python
# Option 1: Pass to constructor
reporter = ReportGenerator(db, export_dir='/var/netsec/reports')

# Option 2: Set environment variable
# export NETSEC_EXPORT_DIR=/var/netsec/reports
reporter = ReportGenerator(db)
```

### Directory Structure

```
exports/
├── report_standard_20240816_143022.html
├── report_standard_20240816_143022.json
├── report_standard_20240816_143022.csv
├── report_standard_20240816_143022.md
├── report_restricted_20240816_145610_CASE-2024-001.pdf
└── executive_summary_2024_q4.html
```

## Report Types

### Standard Reports
- Suitable for general distribution
- Sensitive evidence references are redacted
- Appropriate for executive summaries, client deliverables

### Restricted Reports
- Contains full evidence details and chain of custody
- Only for authorized analysts and investigators
- Includes sensitive findings and raw data references

## API Integration

The export functionality is also available via REST API:

```http
POST /api/reports/export
Content-Type: application/json
Authorization: Bearer <token>

{
  "format": "html",
  "report_type": "standard",
  "case_id": "CASE-2024-001",
  "title": "Monthly Security Report",
  "analyst": "security-team",
  "include_findings": true,
  "include_evidence": false,
  "include_timeline": true
}
```

Response:
```json
{
  "success": true,
  "filepath": "/exports/report_standard_20240816_143022.html",
  "filename": "report_standard_20240816_143022.html",
  "format": "html",
  "size_bytes": 45678,
  "generated_at": "2024-08-16T14:30:22Z"
}
```

## Frontend Integration

A new "Export Report" button is available on the Reports page:

1. Navigate to **Reports** → Select a report
2. Click **Export** button
3. Choose format (HTML, PDF, JSON, CSV, Markdown)
4. Optional: Add custom filename
5. Click **Download**

The file will be generated and downloaded automatically to your browser's download folder.

## Best Practices

### Security
- Use `restricted` reports only when necessary
- Store exported files in secure, access-controlled locations
- Regularly cleanup old exports using `cleanup_old_exports()`
- Encrypt sensitive exported reports at rest

### Performance
- For large datasets, prefer JSON or CSV over HTML/PDF
- Use time range filters to limit report scope
- Export during off-peak hours for large reports
- Monitor export directory disk usage

### Compliance
- Include analyst name and generation timestamp
- Maintain export history for audit trails
- Document report type (standard vs restricted)
- Follow organizational retention policies

## Troubleshooting

### Issue: "Unsupported format" error
**Solution:** Ensure you're using one of: `html`, `pdf`, `json`, `csv`, `md`, `docx`

### Issue: PDF looks like HTML
**Solution:** Install weasyprint: `pip install weasyprint`

### Issue: Export directory not found
**Solution:** Check that the export directory exists and is writable:
```bash
mkdir -p /path/to/exports
chmod 755 /path/to/exports
```

### Issue: Large reports timeout
**Solution:** 
- Reduce time range
- Exclude timeline or evidence if not needed
- Use async export for very large reports

## Future Enhancements

Planned improvements:
- [ ] Native DOCX generation with python-docx
- [ ] PowerPoint/PPTX export for presentations
- [ ] Scheduled automatic report generation
- [ ] Email delivery of reports
- [ ] Custom report templates
- [ ] Chart/graph embedding in PDFs
- [ ] Digital signatures for reports
- [ ] Watermarking for restricted reports

---

*NetSec Platform v1.0.0 - Report Export Module*
