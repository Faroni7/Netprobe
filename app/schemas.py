"""
BlackBox Recon Pydantic Schemas
Phase 2: Target Management - Request/Response validation schemas
"""
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime


# ============== Target Schemas ==============

class TargetBase(BaseModel):
    """Base schema for Target"""
    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=512)
    notes: Optional[str] = None


class TargetCreate(TargetBase):
    """Schema for creating a Target"""
    pass


class TargetUpdate(BaseModel):
    """Schema for updating a Target"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    url: Optional[str] = Field(None, min_length=1, max_length=512)
    notes: Optional[str] = None
    is_active: Optional[bool] = None


class TargetResponse(TargetBase):
    """Schema for Target response"""
    id: int
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# ============== Scan Schemas ==============

class ScanBase(BaseModel):
    """Base schema for Scan"""
    target_id: int


class ScanCreate(ScanBase):
    """Schema for creating a Scan"""
    pass


class ScanResponse(BaseModel):
    """Schema for Scan response"""
    id: int
    target_id: int
    status: str
    progress: float
    current_phase: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanStatusUpdate(BaseModel):
    """Schema for updating scan status"""
    status: str
    progress: Optional[float] = None
    current_phase: Optional[str] = None
    error_message: Optional[str] = None


# ============== ScanEvent Schemas ==============

class ScanEventBase(BaseModel):
    """Base schema for ScanEvent"""
    phase_name: str
    phase_order: int


class ScanEventCreate(ScanEventBase):
    """Schema for creating a ScanEvent"""
    scan_id: int


class ScanEventResponse(ScanEventBase):
    """Schema for ScanEvent response"""
    id: int
    scan_id: int
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============== Finding Schemas ==============

class FindingBase(BaseModel):
    """Base schema for Finding"""
    finding_type: str
    severity: str = "info"
    title: str
    description: Optional[str] = None
    location: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class FindingCreate(FindingBase):
    """Schema for creating a Finding"""
    scan_id: int
    extra_data: Optional[Dict[str, Any]] = None


class FindingResponse(FindingBase):
    """Schema for Finding response"""
    id: int
    scan_id: int
    extra_data: Optional[Dict[str, Any]] = None
    is_false_positive: bool = False
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============== Graph Node Schemas ==============

class GraphNodeBase(BaseModel):
    """Base schema for GraphNode"""
    node_id: str
    node_type: str
    label: str
    parent_id: Optional[str] = None
    depth: int = 0


class GraphNodeCreate(GraphNodeBase):
    """Schema for creating a GraphNode"""
    scan_id: int
    extra_data: Optional[Dict[str, Any]] = None


class GraphNodeResponse(GraphNodeBase):
    """Schema for GraphNode response"""
    id: int
    scan_id: int
    extra_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class GraphNodeTree(BaseModel):
    """Schema for tree-structured graph node"""
    id: str
    label: str
    type: str
    children: List['GraphNodeTree'] = []
    extra_data: Optional[Dict[str, Any]] = None


# ============== Report Schemas ==============

class ReportSummary(BaseModel):
    """Summary statistics for a report"""
    total_endpoints: int = 0
    api_routes: int = 0
    authentication_mechanisms: int = 0
    debug_interfaces: int = 0
    suspicious_parameters: int = 0
    possible_vulns: int = 0
    missing_controls: int = 0


class ReportPhaseResult(BaseModel):
    """Results from a single phase"""
    phase_name: str
    phase_order: int
    status: str
    findings_count: int
    data: Optional[Dict[str, Any]] = None


class FullReport(BaseModel):
    """Complete scan report"""
    scan_id: int
    target_name: str
    target_url: str
    status: str
    summary: ReportSummary
    phases: List[ReportPhaseResult]
    endpoints: List[str]
    graph_tree: Optional[GraphNodeTree] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


# ============== API Response Wrappers ==============

class APIResponse(BaseModel):
    """Generic API response wrapper"""
    success: bool
    message: str
    data: Optional[Any] = None


class PaginatedResponse(BaseModel):
    """Paginated list response"""
    items: List[Any]
    total: int
    page: int = 1
    per_page: int = 20
    pages: int = 1
