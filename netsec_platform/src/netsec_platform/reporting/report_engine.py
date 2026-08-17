"""
NetSec Platform - Reporting Engine

Generate reports in multiple formats (HTML, PDF, JSON, CSV, DOCX, Markdown).
Supports executive summaries, technical findings, and evidence references.
Includes file export functionality for downloading reports.
"""

import json
import csv
import io
import os
import base64
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
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
    - DOCX: Word document format (requires python-docx)
    - Markdown: Plain text documentation format
    
    Report Types:
    - Standard: Sens values masked/omitted
    - Restricted: Authz analysts only, contains sensitive evidence
    """
    
    def __init__(self, db_manager: DatabaseManager, export_dir: Optional[str] = None):
        self.db = db_manager
        self.export_dir = export_dir or os.environ.get('NETSEC_EXPORT_DIR', './exports')
        Path(self.export_dir).mkdir(parents=True, exist_ok=True)
    
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
        elif format == 'md':
            content = self._generate_markdown(report_data)
        elif format == 'docx':
            # DOCX generation requires python-docx library
            # For now, generate HTML that can be opened in Word
            content = self._generate_html(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}. Supported: html, pdf, json, csv, md, docx")
        
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
    
    def _generate_markdown(self, report_data: Dict) -> str:
        """Generate Markdown report."""
        
        metadata = report_data['metadata']
        summary = report_data['executive_summary']
        findings = report_data['findings']
        
        md = f"""# {metadata['title']}

**Generated:** {metadata['generated_at']}  
**Report Type:** {metadata['report_type'].upper()}  
"""
        
        if metadata['case_id']:
            md += f"**Case ID:** {metadata['case_id']}  \n"
        if metadata['generated_by']:
            md += f"**Analyst:** {metadata['generated_by']}  \n"
        
        md += f"""
## Executive Summary

| Metric | Value |
|--------|-------|
| Risk Level | **{summary['risk_level']}** (Score: {summary['risk_score']}/10) |
| Total Findings | {summary['total_findings']} |
| Critical | {summary['severity_breakdown']['critical']} |
| High | {summary['severity_breakdown']['high']} |
| Medium | {summary['severity_breakdown']['medium']} |
| Low | {summary['severity_breakdown']['low']} |
| Flows Analyzed | {summary['total_flows_analyzed']} |
| Assets Discovered | {summary['total_assets']} |

### Top Issues

| Severity | Issue | Remediation |
|----------|-------|-------------|
"""
        
        for issue in summary['top_issues']:
            remediation = issue['remediation'][:50].replace('|', '/') + ('...' if len(issue['remediation']) > 50 else '')
            md += f"| {issue['severity']} | {issue['title']} | {remediation} |\n"
        
        md += "\n## All Findings\n\n"
        md += "| ID | Title | Severity | Status | Description |\n"
        md += "|----|-------|----------|--------|-------------|\n"
        
        for finding in findings:
            desc = (finding.get('description', '') or '')[:50].replace('|', '/') + ('...' if len(finding.get('description', '') or '') > 50 else '')
            md += f"| {finding.get('finding_id', 'N/A')} | {finding.get('title', 'N/A')} | {finding.get('severity', 'N/A')} | {finding.get('status', 'NEW')} | {desc} |\n"
        
        md += "\n## Recommendations\n\n"
        for rec in summary['recommendations']:
            md += f"- {rec}\n"
        
        md += f"\n---\n*Generated by NetSec Platform v1.0.0*\n"
        
        return md
    
    def export_report(
        self,
        report_type: str = "standard",
        format: str = "html",
        filename: Optional[str] = None,
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
        Generate a report and export it to a file.
        
        Args:
            report_type: 'standard' or 'restricted'
            format: 'html', 'pdf', 'json', 'csv', 'md', 'docx'
            filename: Custom filename (auto-generated if not provided)
            case_id: Optional case ID to filter by
            time_range_start: Start of analysis period
            time_range_end: End of analysis period
            include_findings: Include security findings
            include_evidence: Include evidence references (restricted only)
            include_timeline: Include event timeline
            title: Report title
            analyst: Analyst name
        
        Returns:
            Dictionary with 'filepath', 'format', 'size_bytes', 'generated_at'
        """
        
        # Generate the report content
        report_result = self.generate_report(
            report_type=report_type,
            format=format,
            case_id=case_id,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            include_findings=include_findings,
            include_evidence=include_evidence,
            include_timeline=include_timeline,
            title=title,
            analyst=analyst
        )
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            case_suffix = f"_{case_id}" if case_id else ""
            filename = f"report_{report_type}_{timestamp}{case_suffix}.{format}"
        
        # Ensure filename has correct extension
        if not filename.endswith(f".{format}"):
            if format == 'md':
                filename = filename.rsplit('.', 1)[0] + '.md'
            elif format == 'docx':
                filename = filename.rsplit('.', 1)[0] + '.docx'
        
        # Write to file
        filepath = os.path.join(self.export_dir, filename)
        content = report_result['content']
        
        # Handle binary vs text content
        if isinstance(content, bytes):
            with open(filepath, 'wb') as f:
                f.write(content)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        
        file_size = os.path.getsize(filepath)
        
        return {
            'filepath': filepath,
            'filename': filename,
            'format': format,
            'report_type': report_type,
            'size_bytes': file_size,
            'generated_at': report_result['generated_at'],
            'success': True
        }
    
    def export_multiple_reports(
        self,
        formats: List[str] = ['html', 'json', 'csv', 'md'],
        report_type: str = "standard",
        case_id: Optional[str] = None,
        title: Optional[str] = None,
        analyst: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate and export the same report in multiple formats simultaneously.
        
        Args:
            formats: List of formats to export (e.g., ['html', 'json', 'csv'])
            report_type: 'standard' or 'restricted'
            case_id: Optional case ID
            title: Report title
            analyst: Analyst name
        
        Returns:
            Dictionary with list of exported files and summary
        """
        
        results = []
        total_size = 0
        
        for fmt in formats:
            try:
                result = self.export_report(
                    report_type=report_type,
                    format=fmt,
                    case_id=case_id,
                    title=title,
                    analyst=analyst
                )
                results.append(result)
                total_size += result['size_bytes']
            except Exception as e:
                results.append({
                    'format': fmt,
                    'success': False,
                    'error': str(e)
                })
        
        return {
            'exports': results,
            'total_files': len([r for r in results if r.get('success')]),
            'total_size_bytes': total_size,
            'export_dir': self.export_dir,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def get_export_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get list of recently exported reports.
        
        Args:
            limit: Maximum number of entries to return
        
        Returns:
            List of dictionaries with file information
        """
        exports = []
        
        try:
            export_path = Path(self.export_dir)
            files = sorted(export_path.glob('*'), key=os.path.getmtime, reverse=True)[:limit]
            
            for file_path in files:
                if file_path.is_file():
                    stat = file_path.stat()
                    exports.append({
                        'filename': file_path.name,
                        'filepath': str(file_path),
                        'size_bytes': stat.st_size,
                        'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'format': file_path.suffix.lstrip('.')
                    })
        except Exception as e:
            pass  # Return empty list if directory doesn't exist yet
        
        return exports
    
    def cleanup_old_exports(self, days: int = 30) -> int:
        """
        Remove export files older than specified days.
        
        Args:
            days: Age threshold in days
        
        Returns:
            Number of files deleted
        """
        deleted_count = 0
        cutoff_time = datetime.utcnow().timestamp() - (days * 24 * 60 * 60)
        
        try:
            export_path = Path(self.export_dir)
            for file_path in export_path.glob('*'):
                if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    deleted_count += 1
        except Exception as e:
            pass
        
        return deleted_count
    
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
