"""
BlackBox Recon - Reconnaissance Pipeline
Phase 3: Reconnaissance Engine - Orchestrates all recon phases
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.recon.base import BaseReconPhase
from app.recon.dns_discovery import DNSDiscoveryPhase
from app.recon.http_fingerprinting import HTTPFingerprintingPhase
from app.recon.tech_detection import TechDetectionPhase
from app.recon.js_analysis import JSAnalysisPhase
from app.recon.param_discovery import ParamDiscoveryPhase
from app.recon.security_headers import SecurityHeadersPhase
from app.recon.api_discovery import APIDiscoveryPhase
from app.recon.vuln_classification import VulnClassificationPhase
from app.recon.graph_builder import GraphBuilderPhase

from app.models import Scan, ScanEvent, Finding, GraphNode
from app.config import settings


class ReconPipeline:
    """
    Orchestrates the reconnaissance pipeline.
    Executes phases in order and stores results in the database.
    """
    
    def __init__(self, target_url: str, scan_id: int, db_session: AsyncSession):
        self.target_url = target_url
        self.scan_id = scan_id
        self.db = db_session
        self.stop_requested = False
        
        # Initialize all phases in execution order
        self.phases: List[BaseReconPhase] = [
            DNSDiscoveryPhase(target_url, scan_id, db_session),
            HTTPFingerprintingPhase(target_url, scan_id, db_session),
            TechDetectionPhase(target_url, scan_id, db_session),
            JSAnalysisPhase(target_url, scan_id, db_session),
            ParamDiscoveryPhase(target_url, scan_id, db_session),
            SecurityHeadersPhase(target_url, scan_id, db_session),
            APIDiscoveryPhase(target_url, scan_id, db_session),
            VulnClassificationPhase(target_url, scan_id, db_session),
            GraphBuilderPhase(target_url, scan_id, db_session),
        ]
    
    def request_stop(self):
        """Request graceful stop of the pipeline."""
        self.stop_requested = True
    
    async def _update_scan_status(self, status: str, progress: float = None, 
                                   current_phase: str = None, error_message: str = None):
        """Update the scan record in the database."""
        from sqlalchemy import update
        
        update_data = {"status": status}
        if progress is not None:
            update_data["progress"] = progress
        if current_phase is not None:
            update_data["current_phase"] = current_phase
        if error_message is not None:
            update_data["error_message"] = error_message
        if status == "running" and not error_message:
            update_data["started_at"] = datetime.now()
        if status in ["completed", "failed", "stopped"]:
            update_data["completed_at"] = datetime.now()
        
        await self.db.execute(
            update(Scan).where(Scan.id == self.scan_id).values(**update_data)
        )
        await self.db.commit()
    
    async def _store_event(self, event_data: Dict[str, Any]):
        """Store a phase event in the database."""
        event = ScanEvent(
            scan_id=self.scan_id,
            phase_name=event_data["phase_name"],
            phase_order=event_data["phase_order"],
            status=event_data["status"],
            started_at=datetime.fromisoformat(event_data["started_at"]) if event_data.get("started_at") else None,
            completed_at=datetime.fromisoformat(event_data["completed_at"]) if event_data.get("completed_at") else None,
            result_data=event_data.get("result_data", {}),
            error_message=event_data.get("error_message"),
        )
        self.db.add(event)
        await self.db.commit()
        return event.id
    
    async def _store_findings(self, findings: List[Dict[str, Any]]):
        """Store findings in the database."""
        for finding_data in findings:
            finding = Finding(
                scan_id=self.scan_id,
                finding_type=finding_data.get("finding_type", "unknown"),
                severity=finding_data.get("severity", "info"),
                title=finding_data.get("title", ""),
                description=finding_data.get("description", ""),
                location=finding_data.get("location", ""),
                evidence=finding_data.get("evidence", ""),
                remediation=finding_data.get("remediation", ""),
                metadata=finding_data.get("metadata", {}),
            )
            self.db.add(finding)
        await self.db.commit()
    
    async def run(self) -> Dict[str, Any]:
        """
        Execute the full reconnaissance pipeline.
        Returns summary of results.
        """
        total_phases = len(self.phases)
        completed_phases = 0
        all_results = []
        all_findings = []
        
        await self._update_scan_status("running", progress=0)
        
        for phase in self.phases:
            if self.stop_requested:
                await self._update_scan_status("stopped", progress=(completed_phases / total_phases) * 100)
                break
            
            # Update current phase status
            await self._update_scan_status(
                "running",
                progress=(completed_phases / total_phases) * 100,
                current_phase=phase.name
            )
            
            # Execute phase
            result = await phase.run()
            all_results.append(result)
            
            # Store event
            await self._store_event(result)
            
            # Store any findings
            if result.get("findings"):
                await self._store_findings(result["findings"])
                all_findings.extend(result["findings"])
            
            completed_phases += 1
        
        # Determine final status
        final_status = "completed" if completed_phases == total_phases else "stopped"
        await self._update_scan_status(
            final_status,
            progress=100.0,
            current_phase=None
        )
        
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": final_status,
            "phases_completed": completed_phases,
            "total_phases": total_phases,
            "total_findings": len(all_findings),
            "results": all_results
        }
