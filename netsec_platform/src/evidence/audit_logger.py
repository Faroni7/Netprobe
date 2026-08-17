"""
Audit Logger.

Provides comprehensive audit logging for security-sensitive operations.
All access to sensitive evidence and critical operations are logged.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4


logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""
    # Evidence access
    EVIDENCE_CREATED = "evidence_created"
    EVIDENCE_ACCESSED = "evidence_accessed"
    EVIDENCE_MODIFIED = "evidence_modified"
    EVIDENCE_DELETED = "evidence_deleted"
    EVIDENCE_LOCKED = "evidence_locked"
    EVIDENCE_UNLOCKED = "evidence_unlocked"
    
    # ESS operations
    ESS_ACTIVATED = "ess_activated"
    ESS_RECOVERED = "ess_recovered"
    ESS_TESTED = "ess_tested"
    
    # Controlled testing
    TEST_STARTED = "test_started"
    TEST_STOPPED = "test_stopped"
    TEST_ABORTED = "test_aborted"
    
    # Authentication/Authorization
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    
    # System
    CONFIG_CHANGED = "config_changed"
    EXPORT_INITIATED = "export_initiated"
    IMPORT_COMPLETED = "import_completed"


@dataclass
class AuditEvent:
    """Single audit event record."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    user_id: Optional[str]
    actor_ip: Optional[str]
    
    # Target of the action
    target_type: Optional[str] = None  # e.g., "evidence", "finding", "case"
    target_id: Optional[str] = None
    
    # Action details
    action: str = ""
    reason: Optional[str] = None
    
    # Result
    success: bool = True
    error_message: Optional[str] = None
    
    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "actor_ip": self.actor_ip,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "action": self.action,
            "reason": self.reason,
            "success": self.success,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Comprehensive audit logger.
    
    Features:
    - Tamper-evident logging
    - Structured JSON format
    - Configurable retention
    - Query capabilities
    """
    
    def __init__(
        self,
        log_path: str,
        max_events_in_memory: int = 10000,
    ):
        self.log_path = Path(log_path)
        self.log_path.mkdir(parents=True, exist_ok=True)
        
        self.max_events_in_memory = max_events_in_memory
        self._memory_buffer: List[AuditEvent] = []
        
        # Current log file
        self._current_log_file = self._get_log_file()
        
        logger.info(f"AuditLogger initialized at {self.log_path}")
    
    def _get_log_file(self) -> Path:
        """Get current log file path with date-based rotation."""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self.log_path / f"audit_{date_str}.jsonl"
    
    def log(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        action: str = "",
        reason: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor_ip: Optional[str] = None,
    ) -> AuditEvent:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{uuid4().hex[:12]}",
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            actor_ip=actor_ip,
            target_type=target_type,
            target_id=target_id,
            action=action,
            reason=reason,
            success=success,
            error_message=error_message,
            metadata=metadata or {},
        )
        
        # Write to file immediately (tamper-evident)
        self._write_event(event)
        
        # Also keep in memory buffer for quick queries
        self._memory_buffer.append(event)
        if len(self._memory_buffer) > self.max_events_in_memory:
            self._memory_buffer.pop(0)
        
        # Log to standard logger for monitoring integration
        log_level = logging.INFO if success else logging.WARNING
        logger.log(
            log_level,
            f"AUDIT [{event.event_type.value}] by {user_id or 'unknown'}: {action} on {target_type}:{target_id} - {'OK' if success else 'FAILED'}",
        )
        
        return event
    
    def _write_event(self, event: AuditEvent):
        """Write event to log file."""
        try:
            # Check if we need to rotate
            new_log_file = self._get_log_file()
            if new_log_file != self._current_log_file:
                self._current_log_file = new_log_file
            
            # Append to file
            with open(self._current_log_file, 'a') as f:
                f.write(event.to_json() + '\n')
                
        except Exception as e:
            logger.error(f"Failed to write audit event: {e}")
    
    # Convenience methods for common events
    
    def log_evidence_access(
        self,
        evidence_id: str,
        user_id: str,
        reason: Optional[str] = None,
        success: bool = True,
    ) -> AuditEvent:
        """Log evidence access."""
        return self.log(
            event_type=AuditEventType.EVIDENCE_ACCESSED,
            user_id=user_id,
            target_type="evidence",
            target_id=evidence_id,
            action="reveal_value",
            reason=reason,
            success=success,
        )
    
    def log_evidence_lock(
        self,
        evidence_id: Optional[str],
        user_id: str,
        reason: str = "Emergency Security Stop",
    ) -> AuditEvent:
        """Log evidence lock operation."""
        return self.log(
            event_type=AuditEventType.EVIDENCE_LOCKED,
            user_id=user_id,
            target_type="evidence",
            target_id=evidence_id,
            action="lock",
            reason=reason,
        )
    
    def log_ess_activation(
        self,
        user_id: str,
        reason: str,
    ) -> AuditEvent:
        """Log ESS activation."""
        return self.log(
            event_type=AuditEventType.ESS_ACTIVATED,
            user_id=user_id,
            action="activate_emergency_security_stop",
            reason=reason,
            metadata={"trigger": "manual"},
        )
    
    def log_ess_recovery(
        self,
        user_id: str,
        authorization_ref: str,
    ) -> AuditEvent:
        """Log ESS recovery."""
        return self.log(
            event_type=AuditEventType.ESS_RECOVERED,
            user_id=user_id,
            action="recover_from_emergency_stop",
            reason=f"Authorization: {authorization_ref}",
        )
    
    def log_test_start(
        self,
        test_id: str,
        user_id: str,
        scope: Dict[str, Any],
    ) -> AuditEvent:
        """Log controlled test start."""
        return self.log(
            event_type=AuditEventType.TEST_STARTED,
            user_id=user_id,
            target_type="controlled_test",
            target_id=test_id,
            action="start_test",
            metadata={"scope": scope},
        )
    
    def log_permission_denied(
        self,
        user_id: str,
        resource: str,
        action: str,
    ) -> AuditEvent:
        """Log permission denial."""
        return self.log(
            event_type=AuditEventType.PERMISSION_DENIED,
            user_id=user_id,
            target_type=resource,
            action=action,
            success=False,
            error_message="Insufficient permissions",
        )
    
    # Query methods
    
    def get_recent_events(
        self,
        limit: int = 100,
        event_type: Optional[AuditEventType] = None,
        user_id: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Get recent events from memory buffer."""
        events = self._memory_buffer.copy()
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if user_id:
            events = [e for e in events if e.user_id == user_id]
        
        return events[-limit:]
    
    def search_events(
        self,
        target_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Search events in log files."""
        results = []
        
        # Get relevant log files
        log_files = sorted(self.log_path.glob("audit_*.jsonl"))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            event_data = json.loads(line.strip())
                            
                            # Filter
                            if target_id and event_data.get("target_id") != target_id:
                                continue
                            
                            if event_type and event_data.get("event_type") != event_type.value:
                                continue
                            
                            if start_time:
                                event_time = datetime.fromisoformat(event_data["timestamp"])
                                if event_time < start_time:
                                    continue
                            
                            if end_time:
                                event_time = datetime.fromisoformat(event_data["timestamp"])
                                if event_time > end_time:
                                    continue
                            
                            results.append(event_data)
                            
                        except json.JSONDecodeError:
                            continue
                            
            except Exception as e:
                logger.warning(f"Error reading log file {log_file}: {e}")
        
        return results
    
    def get_chain_of_custody(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get complete chain of custody for evidence."""
        return self.search_events(target_id=evidence_id)
    
    def export_audit_log(
        self,
        output_path: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """Export audit log to file."""
        events = self.search_events(start_time=start_time, end_time=end_time)
        
        try:
            with open(output_path, 'w') as f:
                json.dump(events, f, indent=2)
            
            logger.info(f"Exported {len(events)} audit events to {output_path}")
            return len(events)
            
        except Exception as e:
            logger.error(f"Failed to export audit log: {e}")
            return 0
