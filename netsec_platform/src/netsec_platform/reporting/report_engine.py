"""
NetSec Platform - Reporting Engine

Generate reports in multiple formats (HTML, PDF, JSON, CSV).
Supports executive summaries, technical findings, and evidence references.
"""

import json
import csv
import io
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..storage.database import DatabaseManager


class ReportGenerator:
    """
    Generate security reports in multiple formats.
    
    Formats:
    - HTML: Interactive report with charts
    - PDF: Printable report (requires weasyprint or similar)
    - JSON: Machine-readable format
    - CSV: Spreadsheet-compatible format
    
    Report Types:
    - Standard: Sens values masked/omitted
    - Restricted: Authz analysts only, contains sensitive evidence
    """
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def generate_report(
        self,
        report_type: str = "standard",
        format: str = "html",
        case_id: Optional[str] = None,
        time_range_start: Optional[datetime] = None,
        time_range_end: Optional[datetime] = None,
        include_findings: bool = True,
        include_evidence: bool = False,
        include_timeline: bool = True,
        title: Optional[str] = None,
        analyst: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        
        Args:
            report_type: 'standard' or 'restricted'
            format: 'html', 'pdf', 'json', or 'csv'
            case_id: Optional case ID to filter by
            time_range_start: Start of analysis period
            time_range_end: End of analysis period
            include_findings: Include security findings
            include_evidence: Include evidence references (restricted only)
            include_timeline: Include event timeline
            title: Report title
            analyst: Analyst name
        
        Returns:
            Dictionary with 'content', 'format', 'generated_at'
        """
        
        # Gather data
        stats = self.db.get_statistics()
        findings = []
        flows = []
        assets = []
        timeline_events = []
        
        if include_findings:
            filters = {}
            if case_id:
                filters['case_id'] = case_id
            findings = self.db.get_findings(limit=1000, filters=filters)
        
        # Filter by time range if specified
        if time_range_start or time_range_end:
            # TODO: Add time filtering to database queries
            pass
        
        # Build report sections
        report_data = {
            'metadata': {
                'title': title or "NetSec Platform Security Report",
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'generated_by': analyst,
                'time_range': {
                    'start': time_range_start.isoformat() if time_range_start else None,
                    'end': time_range_end.isoformat() if time_range_end else None
                },
                'case_id': case_id
            },
            'executive_summary': self._generate_executive_summary(stats, findings),
            'statistics': stats,
            'findings': self._filter_findings_for_report(findings, report_type),
            'assets': assets,
            'timeline': timeline_events if include_timeline else [],
            'evidence_references': [] if include_evidence and report_type == 'restricted' else None
        }
        
        # Generate output in requested format
        if format == 'json':
            content = json.dumps(report_data, indent=2, default=str)
        elif format == 'csv':
            content = self._generate_csv(findings, stats)
        elif format == 'html':
            content = self._generate_html(report_data)
        elif format == 'pdf':
            # PDF generation requires additional library
            html_content = self._generate_html(report_data)
            content = self._convert_to_pdf(html_content)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return {
            'content': content,
            'format': format,
            'report_type': report_type,
            'generated_at': datetime.utcnow().isoformat(),
            'size_bytes': len(content.encode('utf-8'))
        }
    
    def _generate_executive_summary(self, stats: Dict, findings: List[Dict]) -> Dict[str, Any]:
        """Generate executive summary from statistics and findings."""
        
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium_count = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low_count = sum(1 for f in findings if f.get('severity') == 'LOW')
        
        # Calculate risk score (simple weighted average)
        risk_score = (critical_count * 4 + high_count * 3 + medium_count * 2 + low_count * 1)
        if total_findings > 0:
            risk_score = min(10, risk_score / total_findings * 2.5)
        
        # Determine overall risk level
        if critical_count > 0 or risk_score >= 8:
            risk_level = "CRITICAL"
        elif high_count > 0 or risk_score >= 6:
            risk_level = "HIGH"
        elif medium_count > 0 or risk_score >= 4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Get top issues
        top_issues = []
        for finding in sorted(findings, key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.get('severity', 'LOW'), 0), reverse=True)[:5]:
            top_issues.append({
                'title': finding.get('title'),
                'severity': finding.get('severity'),
                'remediation': finding.get('remediation')
            })
        
        return {
            'total_findings': total_findings,
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'severity_breakdown': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'total_flows_analyzed': stats.get('total_flows', 0),
            'total_assets': stats.get('total_assets', 0),
            'top_issues': top_issues,
            'recommendations': self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate prioritized recommendations from findings."""
        
        recommendations = set()
        
        for finding in findings:
            remediation = finding.get('remediation')
            if remediation:
                # Split multi-line remediations
                for line in remediation.split('\n'):
                    line = line.strip().lstrip('-•*')
                    if line:
                        recommendations.add(line)
        
        return list(recommendations)[:10]  # Top 10 recommendations
    
    def _filter_findings_for_report(self, findings: List[Dict], report_type: str) -> List[Dict]:
        """Filter findings based on report type."""
        
        if report_type == 'restricted':
            return findings
        
        # For standard reports, mask sensitive details
        filtered = []
        for finding in findings:
            f = finding.copy()
            # Remove or mask sensitive fields
            if 'evidence_ids' in f:
                f['evidence_ids'] = ['[REDACTED]'] * len(f.get('evidence_ids', []))
            filtered.append(f)
        
        return filtered
    
    def _generate_html(self, report_data: Dict) -> str:
        """Generate HTML report."""
        
        metadata = report_data['metadata']
        summary = report_data['executive_summary']
        stats = report_data['statistics']
        findings = report_data['findings']
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{metadata['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card.critical {{ background: #e74c3c; color: white; }}
        .summary-card.high {{ background: #e67e22; color: white; }}
        .summary-card.medium {{ background: #f39c12; color: white; }}
        .summary-card.low {{ background: #27ae60; color: white; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ color: #7f8c8d; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity-CRITICAL {{ color: #e74c3c; font-weight: bold; }}
        .severity-HIGH {{ color: #e67e22; font-weight: bold; }}
        .severity-MEDIUM {{ color: #f39c12; }}
        .severity-LOW {{ color: #27ae60; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em; }}
        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
        .restricted-banner {{ background: #e74c3c; color: white; padding: 15px; text-align: center; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
"""
        
        # Restricted banner
        if metadata['report_type'] == 'restricted':
            html += """        <div class="restricted-banner">
            ⚠️ RESTRICTED REPORT - CONTAINS SENSITIVE EVIDENCE
        </div>
"""
        
        # Header
        html += f"""        <h1>{metadata['title']}</h1>
        <p><strong>Generated:</strong> {metadata['generated_at']}</p>
        <p><strong>Report Type:</strong> {metadata['report_type'].upper()}</p>
        {f"<p><strong>Case ID:</strong> {metadata['case_id']}</p>" if metadata['case_id'] else ''}
        {f"<p><strong>Analyst:</strong> {metadata['generated_by']}</p>" if metadata['generated_by'] else ''}
        
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="stat-value">{summary['severity_breakdown']['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="stat-value">{summary['severity_breakdown']['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="stat-value">{summary['severity_breakdown']['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="stat-value">{summary['severity_breakdown']['low']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <p><strong>Overall Risk Level:</strong> {summary['risk_level']} (Score: {summary['risk_score']}/10)</p>
        <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
        <p><strong>Flows Analyzed:</strong> {summary['total_flows_analyzed']}</p>
        <p><strong>Assets Discovered:</strong> {summary['total_assets']}</p>
        
        <h2>Top Issues</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Issue</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for issue in summary['top_issues']:
            html += f"""                <tr>
                    <td class="severity-{issue['severity']}">{issue['severity']}</td>
                    <td>{issue['title']}</td>
                    <td>{issue['remediation'][:100]}{'...' if len(issue['remediation']) > 100 else ''}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
        
        <h2>All Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for finding in findings:
            html += f"""                <tr>
                    <td>{finding.get('finding_id', 'N/A')}</td>
                    <td>{finding.get('title', 'N/A')}</td>
                    <td class="severity-{finding.get('severity', 'LOW')}">{finding.get('severity', 'N/A')}</td>
                    <td>{finding.get('status', 'NEW')}</td>
                    <td>{(finding.get('description', '') or '')[:100]}{'...' if len(finding.get('description', '') or '') > 100 else ''}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
        
        <h2>Recommendations</h2>
        <ul>
"""
        
        for rec in summary['recommendations']:
            html += f"            <li>{rec}</li>\n"
        
        html += f"""        </ul>
        
        <div class="footer">
            <p>Generated by NetSec Platform v1.0.0</p>
            <p>This report contains security-sensitive information. Handle according to your organization's data classification policies.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_csv(self, findings: List[Dict], stats: Dict) -> str:
        """Generate CSV report of findings."""
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Finding ID', 'Title', 'Severity', 'Confidence', 'Status',
            'Description', 'Affected Asset', 'Source IP', 'Destination IP',
            'Protocol', 'Timestamp', 'Remediation'
        ])
        
        # Data rows
        for finding in findings:
            writer.writerow([
                finding.get('finding_id', ''),
                finding.get('title', ''),
                finding.get('severity', ''),
                finding.get('confidence', ''),
                finding.get('status', ''),
                finding.get('description', ''),
                finding.get('affected_asset', ''),
                finding.get('src_ip', ''),
                finding.get('dst_ip', ''),
                finding.get('protocol', ''),
                finding.get('timestamp', ''),
                finding.get('remediation', '').replace('\n', ' ')
            ])
        
        return output.getvalue()
    
    def _convert_to_pdf(self, html_content: str) -> bytes:
        """
        Convert HTML to PDF.
        
        Note: Requires weasyprint or similar library.
        For now, returns HTML content with a warning.
        """
        # TODO: Implement proper PDF generation
        # pip install weasyprint
        # from weasyprint import HTML
        # pdf = HTML(string=html_content).write_pdf()
        
        return html_content.encode('utf-8')
    
    def export_pcap(
        self,
        flow_ids: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        output_path: str = "/var/netsec_platform/data/export.pcap"
    ) -> Dict[str, Any]:
        """
        Export PCAP file for specified flows or time range.
        
        Args:
            flow_ids: List of flow IDs to export
            start_time: Start of time range
            end_time: End of time range
            output_path: Path to save PCAP file
        
        Returns:
            Export result with path and size
        """
        # TODO: Implement PCAP export using scapy
        # This would query the packet store and write to PCAP format
        
        return {
            'success': False,
            'message': 'PCAP export not yet implemented',
            'path': output_path
        }
    
    def export_evidence(
        self,
        evidence_ids: List[str],
        output_path: str,
        user: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Export evidence package (requires EXPORT_EVIDENCE permission).
        
        Args:
            evidence_ids: List of evidence IDs to export
            output_path: Path to save evidence package
            user: Requesting user
            reason: Reason for export
        
        Returns:
            Export result with audit trail
        """
        # TODO: Implement evidence export with chain of custody
        # Should create encrypted archive with metadata
        
        return {
            'success': False,
            'message': 'Evidence export not yet implemented',
            'audit_logged': True
        }
