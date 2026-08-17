"""
NetSec Platform - REST API

FastAPI-based REST API for network security operations.
Provides endpoints for capture management, querying, evidence access, and ESS.
"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from netsec_platform.config.settings import NetSecConfig, get_default_config, CaptureProfileEnum
from netsec_platform.models.core_models import (
    NetworkFlow, SecurityFinding, SensitiveArtifact,
    EncryptionState, SecurityQuality
)
from netsec_platform.storage.database import DatabaseManager

# Alias for compatibility
CaptureProfile = CaptureProfileEnum
settings = get_default_config()


# ============================================================================
# API Models
# ============================================================================

class CaptureStartRequest(BaseModel):
    interface: str
    profile: str = "standard"
    filter_expression: Optional[str] = None
    max_packets: Optional[int] = None
    max_size_mb: Optional[int] = None
    max_duration_sec: Optional[int] = None


class CaptureStatusResponse(BaseModel):
    session_id: str
    status: str
    interface: str
    profile: str
    packets_captured: int
    packets_dropped: int
    bytes_captured: int
    started_at: Optional[datetime]
    stopped_at: Optional[datetime]


# ============================================================================
# API Application
# ============================================================================

app = FastAPI(
    title="NetSec Platform API",
    description="Network Security Visibility, Traffic Analysis, and Evidence Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

security = HTTPBearer(auto_error=False)

# Global instances (initialized on startup)
db_manager: Optional[DatabaseManager] = None
capture_engine = None
flow_engine = None
detection_engine = None
evidence_store = None
evidence_vault = None
audit_logger = None
ess = None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """Authenticate and return current user."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    return "analyst"  # Placeholder


# ============================================================================
# Lifecycle Events
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize platform components on startup."""
    global db_manager, capture_engine, flow_engine, detection_engine
    global evidence_store, evidence_vault, audit_logger, ess
    
    db_manager = DatabaseManager()
    
    # Lazy imports to avoid circular dependencies
    from netsec_platform.capture.packet_capture import PacketCaptureEngine
    from netsec_platform.flow.flow_engine import FlowEngine
    from netsec_platform.detection.detection_engine import DetectionEngine
    from netsec_platform.evidence.evidence_store import EvidenceStore, EvidenceVault
    from netsec_platform.evidence.audit_logger import AuditLogger
    from netsec_platform.utils.emergency_stop import EmergencySecurityStop
    
    capture_engine = PacketCaptureEngine(db_manager)
    flow_engine = FlowEngine(db_manager)
    detection_engine = DetectionEngine(db_manager)
    evidence_store = EvidenceStore(db_manager)
    evidence_vault = EvidenceVault(db_manager)
    audit_logger = AuditLogger(db_manager)
    ess = EmergencySecurityStop(db_manager, audit_logger)
    
    # Register ESS callbacks
    ess.register_callback("capture", lambda: capture_engine.stop_capture())
    ess.register_callback("processing", lambda: flow_engine.stop_processing())
    ess.register_callback("detection", lambda: detection_engine.stop_detection())
    
    await audit_logger.log_event(
        event_type="SYSTEM_STARTUP",
        actor="system",
        action="PLATFORM_STARTED",
        details={"version": "1.0.0"}
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global db_manager, capture_engine
    
    if capture_engine:
        capture_engine.stop_capture()
    
    if db_manager:
        db_manager.close()


# ============================================================================
# Health Check
# ============================================================================

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "ess_state": ess.state.value if ess else "NOT_INITIALIZED"
    }


# ============================================================================
# Statistics Endpoints
# ============================================================================

@app.get("/api/v1/statistics")
async def get_statistics():
    """Get platform statistics."""
    if db_manager:
        stats = db_manager.get_statistics()
        return stats
    return {"error": "Database not initialized"}
