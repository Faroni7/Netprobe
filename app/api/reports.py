"""
BlackBox Recon - Reports API Router
Phase 9: Reporting - Report generation and export
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Dict, Any, Optional
import json

from app.db import get_db
from app.models import Scan, Target, ScanEvent, Finding, GraphNode
from app.schemas import ReportSummary, FullReport, ReportPhaseResult

router = APIRouter(prefix="/reports", tags=["reports"])


async def build_report_summary(scan_id: int, db: AsyncSession) -> ReportSummary:
    """Build summary statistics for a report."""
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()
    
    summary = ReportSummary(
        total_endpoints=len([f for f in findings if f.finding_type == "endpoint"]),
        api_routes=len([f for f in findings if f.finding_type == "api"]),
        authentication_mechanisms=len([f for f in findings if "auth" in f.finding_type.lower()]),
        debug_interfaces=len([f for f in findings if "debug" in f.title.lower()]),
        suspicious_parameters=len([f for f in findings if f.severity in ["medium", "high"]]),
        possible_vulns=len([f for f in findings if f.severity in ["high", "critical"]]),
        missing_controls=len([f for f in findings if "missing" in f.title.lower()])
    )
    return summary


async def build_graph_tree(scan_id: int, db: AsyncSession) -> Optional[Dict]:
    """Build tree structure from graph nodes."""
    nodes_result = await db.execute(
        select(GraphNode).where(GraphNode.scan_id == scan_id)
    )
    nodes = nodes_result.scalars().all()
    
    if not nodes:
        return None
    
    # Build tree structure
    node_map = {n.node_id: {"id": n.node_id, "label": n.label, "type": n.node_type, "children": [], "extra_data": n.extra_data} for n in nodes}
    root = None
    
    for node in nodes:
        if node.parent_id is None:
            root = node_map[node.node_id]
        elif node.parent_id in node_map:
            node_map[node.parent_id]["children"].append(node_map[node.node_id])
    
    return root


@router.get("/{scan_id}", response_model=FullReport)
async def get_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get full report for a scan."""
    # Get scan with target
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()
    
    # Get events
    events_result = await db.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.phase_order)
    )
    events = events_result.scalars().all()
    
    # Build phases list
    phases = [
        ReportPhaseResult(
            phase_name=e.phase_name,
            phase_order=e.phase_order,
            status=e.status,
            findings_count=len(e.result_data.get("findings", [])) if e.result_data else 0,
            data=e.result_data
        )
        for e in events
    ]
    
    # Get endpoints from findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()
    endpoints = [f.location for f in findings if f.location]
    
    # Build summary
    summary = await build_report_summary(scan_id, db)
    
    # Build graph tree
    graph_tree = await build_graph_tree(scan_id, db)
    
    return FullReport(
        scan_id=scan.id,
        target_name=target.name if target else "Unknown",
        target_url=target.url if target else "",
        status=scan.status,
        summary=summary,
        phases=phases,
        endpoints=endpoints[:100],  # Limit to 100
        graph_tree=graph_tree,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


@router.get("/{scan_id}/export/json")
async def export_json(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export report as JSON."""
    report = await get_report(scan_id, db)
    return JSONResponse(
        content=json.loads(report.model_dump_json()),
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"}
    )


@router.get("/{scan_id}/export/markdown")
async def export_markdown(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export report as Markdown."""
    report = await get_report(scan_id, db)
    
    md = f"""# BlackBox Recon Report

## Target Information
- **Name:** {report.target_name}
- **URL:** {report.target_url}
- **Status:** {report.status}
- **Completed:** {report.completed_at}

## Summary
| Metric | Count |
|--------|-------|
| Endpoints | {report.summary.total_endpoints} |
| API Routes | {report.summary.api_routes} |
| Auth Mechanisms | {report.summary.authentication_mechanisms} |
| Debug Interfaces | {report.summary.debug_interfaces} |
| Suspicious Parameters | {report.summary.suspicious_parameters} |
| Possible Vulnerabilities | {report.summary.possible_vulns} |
| Missing Controls | {report.summary.missing_controls} |

## Phases
"""
    
    for phase in report.phases:
        md += f"\n### {phase.phase_name}\n- Status: {phase.status}\n- Findings: {phase.findings_count}\n"
    
    md += "\n## Endpoints\n"
    for ep in report.endpoints[:50]:
        md += f"- `{ep}`\n"
    
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.md"}
    )


@router.get("/{scan_id}/export/html")
async def export_html(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export report as HTML."""
    report = await get_report(scan_id, db)
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>BlackBox Recon Report - {report.target_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .card .value {{ font-size: 24px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; }}
        .endpoint {{ font-family: monospace; background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>BlackBox Recon Report</h1>
    <p><strong>Target:</strong> {report.target_name} ({report.target_url})</p>
    <p><strong>Status:</strong> {report.status} | <strong>Completed:</strong> {report.completed_at}</p>
    
    <h2>Summary</h2>
    <div class="summary">
        <div class="card"><h3>Endpoints</h3><div class="value">{report.summary.total_endpoints}</div></div>
        <div class="card"><h3>API Routes</h3><div class="value">{report.summary.api_routes}</div></div>
        <div class="card"><h3>Auth Mechanisms</h3><div class="value">{report.summary.authentication_mechanisms}</div></div>
        <div class="card"><h3>Debug Interfaces</h3><div class="value">{report.summary.debug_interfaces}</div></div>
        <div class="card"><h3>Suspicious Params</h3><div class="value">{report.summary.suspicious_parameters}</div></div>
        <div class="card"><h3>Possible Vulns</h3><div class="value">{report.summary.possible_vulns}</div></div>
        <div class="card"><h3>Missing Controls</h3><div class="value">{report.summary.missing_controls}</div></div>
    </div>
    
    <h2>Phases</h2>
    <table>
        <tr><th>Phase</th><th>Status</th><th>Findings</th></tr>
"""
    
    for phase in report.phases:
        html += f"<tr><td>{phase.phase_name}</td><td>{phase.status}</td><td>{phase.findings_count}</td></tr>\n"
    
    html += """
    </table>
    
    <h2>Endpoints</h2>
    <ul>
"""
    
    for ep in report.endpoints[:50]:
        html += f"<li><span class=\"endpoint\">{ep}</span></li>\n"
    
    html += """
    </ul>
</body>
</html>
"""
    
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.html"}
    )
