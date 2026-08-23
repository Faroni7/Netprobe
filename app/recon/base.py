"""
BlackBox Recon - Base Reconnaissance Phase
Phase 3: Reconnaissance Engine - Abstract base class for all phases
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio
import random

from app.config import settings


class BaseReconPhase(ABC):
    """
    Abstract base class for all reconnaissance phases.
    Each phase should inherit from this and implement execute().
    """
    
    # Phase metadata - override in subclasses
    name: str = "base_phase"
    order: int = 0
    description: str = "Base reconnaissance phase"
    
    def __init__(self, target_url: str, scan_id: int, session=None):
        self.target_url = target_url
        self.scan_id = scan_id
        self.session = session  # Database session
        self.results: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        
    async def _delay(self):
        """Apply configurable delay with optional randomization for detection evasion."""
        delay = settings.REQUEST_DELAY
        if settings.RANDOM_DELAY_MAX > settings.RANDOM_DELAY_MIN:
            delay += random.uniform(settings.RANDOM_DELAY_MIN, settings.RANDOM_DELAY_MAX)
        await asyncio.sleep(delay)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with optional User-Agent rotation for detection evasion."""
        user_agents = settings.USER_AGENTS
        selected_ua = random.choice(user_agents) if len(user_agents) > 1 else settings.DEFAULT_USER_AGENT
        
        headers = {
            "User-Agent": selected_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        return headers
    
    async def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[Any]:
        """Make an HTTP request with configured settings."""
        import aiohttp
        
        headers = kwargs.pop('headers', self._get_headers())
        timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)
        
        proxy = settings.PROXY_URL
        if proxy:
            kwargs['proxy'] = proxy
        
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            try:
                async with session.request(method, url, **kwargs) as response:
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": await response.text(),
                        "url": str(response.url)
                    }
            except Exception as e:
                return {"error": str(e)}
    
    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the reconnaissance phase.
        Must be implemented by subclasses.
        
        Returns:
            Dict containing phase results
        """
        pass
    
    async def run(self) -> Dict[str, Any]:
        """
        Run the phase with timing and error handling.
        This is the main entry point called by the pipeline.
        """
        self.started_at = datetime.now()
        try:
            await self._delay()
            result = await self.execute()
            self.results = result
            return {
                "phase_name": self.name,
                "phase_order": self.order,
                "status": "completed",
                "started_at": self.started_at.isoformat(),
                "completed_at": datetime.now().isoformat(),
                "result_data": result,
                "findings": self.findings
            }
        except Exception as e:
            return {
                "phase_name": self.name,
                "phase_order": self.order,
                "status": "failed",
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": datetime.now().isoformat(),
                "error_message": str(e),
                "result_data": {},
                "findings": []
            }
    
    def add_finding(self, finding_type: str, title: str, severity: str = "info",
                    description: str = "", location: str = "", evidence: str = "",
                    remediation: str = "", metadata: Optional[Dict] = None):
        """Add a security finding."""
        self.findings.append({
            "finding_type": finding_type,
            "title": title,
            "severity": severity,
            "description": description,
            "location": location,
            "evidence": evidence,
            "remediation": remediation,
            "metadata": metadata or {}
        })
