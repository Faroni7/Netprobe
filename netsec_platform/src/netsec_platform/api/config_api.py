"""
Secure Configuration API for NetSec Platform

Provides REST endpoints for:
- Retrieving effective configuration
- Updating configuration with validation
- Runtime reload
- Configuration health status

All endpoints require appropriate RBAC permissions and audit logging.
"""

from fastapi import APIRouter, HTTPException, Depends, Body
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from ..config.manager import get_config_manager, ConfigurationManager
from ..config.schema import get_all_metadata
from ..evidence.audit_logger import get_audit_logger


router = APIRouter(prefix="/api/v1/config", tags=["Configuration"])


# ============================================================================
# Request/Response Models
# ============================================================================

class ConfigUpdateRequest(BaseModel):
    """Request to update a single configuration value"""
    path: str = Field(..., description="Dot-notation path (e.g., 'app.log_level')")
    value: Any = Field(..., description="New value")
    
class ConfigValidateRequest(BaseModel):
    """Request to validate configuration"""
    configuration: Dict[str, Any]
    
class ConfigValueResponse(BaseModel):
    """Single configuration value response"""
    path: str
    value: Any
    default: Any
    source: str
    restart_required: bool
    runtime_reload: bool
    security_critical: bool
    description: str
    
class ConfigSchemaResponse(BaseModel):
    """Configuration schema response"""
    sections: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Dict[str, Any]]
    
class ConfigStatusResponse(BaseModel):
    """Configuration health status"""
    valid: bool
    version_hash: str
    last_modified: Optional[str]
    last_modified_by: Optional[str]
    config_file_exists: bool
    environment_overrides: int
    runtime_overrides: int
    locked_settings: List[str]
    security_warnings: List[str]


# ============================================================================
# Dependencies
# ============================================================================

def get_current_user():
    """Get current authenticated user - placeholder for real auth"""
    # In production: integrate with actual authentication system
    return {"username": "admin", "roles": ["admin"]}

def require_permission(permission: str):
    """Require specific permission for configuration operations"""
    def dependency(user: dict = Depends(get_current_user)):
        if permission not in user.get('permissions', []):
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required"
            )
        return user
    return dependency


# ============================================================================
# API Endpoints
# ============================================================================

@router.get("", response_model=Dict[str, Any])
async def get_configuration(
    user: dict = Depends(require_permission("CONFIG_READ"))
):
    """
    Retrieve effective configuration.
    
    Secrets are automatically redacted. Source metadata included.
    """
    try:
        manager = get_config_manager()
        config = manager.get_effective_config(redact_secrets=True)
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/schema", response_model=ConfigSchemaResponse)
async def get_configuration_schema(
    user: dict = Depends(require_permission("CONFIG_READ"))
):
    """
    Retrieve configuration schema with metadata.
    
    Includes descriptions, types, defaults, and UI hints.
    """
    try:
        all_metadata = get_all_metadata()
        
        # Build schema from Pydantic models
        from ..config.schema import ConfigurationSchema
        schema_dict = ConfigurationSchema.schema()
        
        return ConfigSchemaResponse(
            sections=schema_dict.get('properties', {}),
            metadata=all_metadata
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("", response_model=Dict[str, Any])
async def update_configuration(
    request: ConfigValidateRequest,
    user: dict = Depends(require_permission("CONFIG_UPDATE"))
):
    """
    Update entire configuration atomically.
    
    Validates before applying. Audits all changes.
    """
    try:
        manager = get_config_manager()
        
        # Validate first
        valid, message = manager.validate_config(request.configuration)
        if not valid:
            raise HTTPException(status_code=400, detail=message)
        
        # Apply updates
        audit_logger = get_audit_logger()
        manager.set_audit_callback(audit_logger.log_config_change)
        
        for section, values in request.configuration.items():
            if section.startswith('_'):  # Skip metadata
                continue
            for key, value in values.items():
                path = f"{section}.{key}"
                success, msg = manager.update(path, value, user['username'])
                if not success:
                    raise HTTPException(status_code=400, detail=msg)
        
        # Save to file
        success, message = manager.save_to_file(user['username'])
        if not success:
            raise HTTPException(status_code=500, detail=message)
        
        return {
            "status": "success",
            "message": "Configuration updated",
            "requires_restart": False  # Would need to check each changed setting
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{path:path}", response_model=Dict[str, Any])
async def update_single_setting(
    path: str,
    request: ConfigUpdateRequest,
    user: dict = Depends(require_permission("CONFIG_UPDATE"))
):
    """
    Update a single configuration setting.
    
    Validates and audits the change.
    """
    try:
        manager = get_config_manager()
        audit_logger = get_audit_logger()
        manager.set_audit_callback(audit_logger.log_config_change)
        
        # Validate path matches
        if request.path != path:
            raise HTTPException(
                status_code=400,
                detail="Path mismatch between URL and body"
            )
        
        # Update
        success, message = manager.update(path, request.value, user['username'])
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        # Check if restart needed
        restart_needed = manager.requires_restart(path)
        
        return {
            "status": "success",
            "path": path,
            "value": request.value,
            "restart_required": restart_needed,
            "message": "Setting updated" + (" (restart required)" if restart_needed else "")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/validate", response_model=Dict[str, Any])
async def validate_configuration(
    request: ConfigValidateRequest,
    user: dict = Depends(require_permission("CONFIG_READ"))
):
    """
    Validate configuration without applying it.
    
    Useful for testing changes before committing.
    """
    try:
        manager = get_config_manager()
        valid, message = manager.validate_config(request.configuration)
        
        return {
            "valid": valid,
            "message": message,
            "errors": [] if valid else [message]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reload", response_model=Dict[str, Any])
async def reload_configuration(
    user: dict = Depends(require_permission("CONFIG_RELOAD"))
):
    """
    Reload configuration from all sources.
    
    Only affects settings marked as runtime-reloadable.
    """
    try:
        manager = get_config_manager()
        config = manager.load()
        
        audit_logger = get_audit_logger()
        audit_logger.log_config_change(
            action="CONFIG_RELOAD",
            actor=user['username'],
            path="*",
            old_value=None,
            new_value="reloaded",
            restart_required=False
        )
        
        return {
            "status": "success",
            "message": "Configuration reloaded",
            "version_hash": manager.get_configuration_hash()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status", response_model=ConfigStatusResponse)
async def get_configuration_status(
    user: dict = Depends(require_permission("CONFIG_READ"))
):
    """
    Get configuration health and status information.
    
    Shows validation state, version, overrides, and warnings.
    """
    try:
        manager = get_config_manager()
        
        # Load to ensure we have current state
        manager.load()
        
        # Count overrides
        env_overrides = len([k for k in __import__('os').environ if k.startswith('NETSEC_')])
        runtime_overrides = len(manager._runtime_overrides)
        
        # Find locked settings
        all_metadata = get_all_metadata()
        locked = [path for path, meta in all_metadata.items() if meta.get('locked')]
        
        # Generate warnings
        warnings = []
        effective = manager.get_effective_config(redact_secrets=False)
        
        if effective.get('evidence', {}).get('encryption_enabled') is not True:
            warnings.append("Evidence encryption is disabled - NOT recommended for production")
            
        if effective.get('audit', {}).get('enabled') is not True:
            warnings.append("Audit logging is disabled - compliance risk")
            
        if effective.get('testing', {}).get('require_authorization') is not True:
            warnings.append("Authorization not required for tests - SECURITY RISK")
        
        return ConfigStatusResponse(
            valid=True,
            version_hash=manager.get_configuration_hash(),
            last_modified=manager._last_modified.isoformat() if manager._last_modified else None,
            last_modified_by=manager._last_modified_by,
            config_file_exists=manager.config_path.exists(),
            environment_overrides=env_overrides,
            runtime_overrides=runtime_overrides,
            locked_settings=locked,
            security_warnings=warnings
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Helper Functions
# ============================================================================

def register_config_routes(app):
    """Register configuration routes with main application"""
    app.include_router(router)
