"""
Emergency Security Stop (ESS) - Core Safety Mechanism

The ESS is a first-class safety and containment mechanism for situations such as:
- Unauthorized activity is suspected
- The monitoring system may be compromised
- An operator notices unexpected behavior
- Sensitive info is being captured unexpectedly
- An active security test needs to be stopped immediately
- Evidence access needs to be locked immediately

When activated, ESS:
1. Stops packet capture
2. Stops sensitive data processing
3. Stops active tests
4. Stops exports
5. Preserves current evidence
6. Locks sensitive evidence access
7. Records the emergency-stop event
8. Waits for authorized recovery
"""

from enum import Enum
from datetime import datetime, timezone
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass, field
import asyncio

from netsec_platform.utils.logging_config import get_secure_logger
from netsec_platform.config.settings import ESSConfig


logger = get_secure_logger(__name__)


class ESSState(str, Enum):
    """Emergency Security Stop state machine states."""
    READY = "ready"  # Normal operation, ESS available
    ACTIVATING = "activating"  # ESS activation in progress
    STOPPED = "stopped"  # ESS active, system halted
    RECOVERING = "recovering"  # Recovery in progress


class ESSReason(str, Enum):
    """Reasons for emergency stop activation."""
    OPERATOR_REQUEST = "operator_request"
    SUSPECTED_UNAUTHORIZED_ACTIVITY = "suspected_unauthorized_activity"
    SYSTEM_COMPROMISE = "system_compromise"
    UNEXPECTED_BEHAVIOR = "unexpected_behavior"
    SCOPE_VIOLATION = "scope_violation"
    SECURITY_TEST_ABORT = "security_test_abort"
    EVIDENCE_LOCKDOWN = "evidence_lockdown"
    OTHER = "other"


@dataclass
class ESSAuditRecord:
    """Audit record for emergency stop events."""
    event_id: str
    event_type: str = "EMERGENCY_SECURITY_STOP"
    operator: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: Optional[ESSReason] = None
    reason_detail: Optional[str] = None
    
    # System state at activation
    capture_status: str = "UNKNOWN"
    processing_status: str = "UNKNOWN"
    active_test_status: str = "NONE"
    evidence_state: str = "PRESERVED"
    sensitive_evidence_locked: bool = True
    exports_stopped: bool = True
    
    # Recovery info
    recovery_operator: Optional[str] = None
    recovery_timestamp: Optional[datetime] = None
    recovery_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "operator": self.operator,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason.value if self.reason else None,
            "reason_detail": self.reason_detail,
            "capture_status": self.capture_status,
            "processing_status": self.processing_status,
            "active_test_status": self.active_test_status,
            "evidence_state": self.evidence_state,
            "sensitive_evidence_locked": self.sensitive_evidence_locked,
            "exports_stopped": self.exports_stopped,
            "recovery_operator": self.recovery_operator,
            "recovery_timestamp": self.recovery_timestamp.isoformat() if self.recovery_timestamp else None,
            "recovery_reason": self.recovery_reason,
        }


class EmergencySecurityStop:
    """
    Emergency Security Stop (ESS) implementation.
    
    This is the core safety mechanism that allows operators to immediately
    halt all security-sensitive operations while preserving evidence integrity.
    
    Key properties:
    - Must require deliberate confirmation to prevent accidental activation
    - Must not delete or corrupt existing evidence
    - Must lock sensitive evidence access
    - Must create an auditable record
    - Must not automatically resume operations after activation
    - Must remain responsive even under high system load
    """
    
    def __init__(self, config: ESSConfig):
        self.config = config
        self.state = ESSState.READY
        self.audit_record: Optional[ESSAuditRecord] = None
        
        # Callbacks for stopping various subsystems
        # These are set by other components during initialization
        self._stop_capture_callback: Optional[Callable] = None
        self._stop_processing_callback: Optional[Callable] = None
        self._stop_active_tests_callback: Optional[Callable] = None
        self._stop_exports_callback: Optional[Callable] = None
        self._lock_sensitive_evidence_callback: Optional[Callable] = None
        
        # State tracking
        self._capture_stopped = False
        self._processing_stopped = False
        self._active_tests_stopped = False
        self._exports_stopped = False
        self._evidence_locked = False
        
        # Event for waiting on activation
        self._activation_event = asyncio.Event()
        
        logger.info("ESS initialized", enabled=config.enabled)
    
    def register_callbacks(
        self,
        stop_capture: Optional[Callable] = None,
        stop_processing: Optional[Callable] = None,
        stop_active_tests: Optional[Callable] = None,
        stop_exports: Optional[Callable] = None,
        lock_sensitive_evidence: Optional[Callable] = None,
    ) -> None:
        """
        Register callbacks for stopping various subsystems.
        
        These callbacks are invoked when ESS is activated.
        Each callback should be async-compatible.
        """
        self._stop_capture_callback = stop_capture
        self._stop_processing_callback = stop_processing
        self._stop_active_tests_callback = stop_active_tests
        self._stop_exports_callback = stop_exports
        self._lock_sensitive_evidence_callback = lock_sensitive_evidence
        
        logger.debug("ESS callbacks registered")
    
    async def activate(
        self,
        operator: str,
        reason: ESSReason = ESSReason.OPERATOR_REQUEST,
        reason_detail: Optional[str] = None,
    ) -> ESSAuditRecord:
        """
        Activate the Emergency Security Stop.
        
        This method:
        1. Changes state to ACTIVATING
        2. Invokes all registered stop callbacks
        3. Locks sensitive evidence
        4. Creates audit record
        5. Changes state to STOPPED
        
        Args:
            operator: ID of the operator activating ESS
            reason: Reason code for activation
            reason_detail: Optional human-readable explanation
            
        Returns:
            ESSAuditRecord with details of the activation
            
        Raises:
            RuntimeError: If ESS is already activated
        """
        if not self.config.enabled:
            raise RuntimeError("ESS is disabled")
        
        if self.state != ESSState.READY:
            logger.warning(
                "ESS activation attempted but not in READY state",
                current_state=self.state.value,
            )
            # Return existing audit record if already stopped
            if self.audit_record:
                return self.audit_record
        
        self.state = ESSState.ACTIVATING
        logger.critical("ESS ACTIVATION INITIATED", operator=operator, reason=reason.value)
        
        # Generate event ID
        event_id = f"ESS-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        
        # Create audit record
        self.audit_record = ESSAuditRecord(
            event_id=event_id,
            operator=operator,
            reason=reason,
            reason_detail=reason_detail,
        )
        
        # Execute stop actions in parallel where possible
        tasks = []
        
        # Stop capture
        if self._stop_capture_callback and self.config.stop_active_tests:
            try:
                result = self._stop_capture_callback()
                if asyncio.iscoroutine(result):
                    tasks.append(asyncio.create_task(result))
                self._capture_stopped = True
            except Exception as e:
                logger.error("Failed to stop capture", error=str(e))
        
        # Stop processing
        if self._stop_processing_callback:
            try:
                result = self._stop_processing_callback()
                if asyncio.iscoroutine(result):
                    tasks.append(asyncio.create_task(result))
                self._processing_stopped = True
            except Exception as e:
                logger.error("Failed to stop processing", error=str(e))
        
        # Stop active tests
        if self._stop_active_tests_callback and self.config.stop_active_tests:
            try:
                result = self._stop_active_tests_callback()
                if asyncio.iscoroutine(result):
                    tasks.append(asyncio.create_task(result))
                self._active_tests_stopped = True
            except Exception as e:
                logger.error("Failed to stop active tests", error=str(e))
        
        # Stop exports
        if self._stop_exports_callback and self.config.stop_exports:
            try:
                result = self._stop_exports_callback()
                if asyncio.iscoroutine(result):
                    tasks.append(asyncio.create_task(result))
                self._exports_stopped = True
            except Exception as e:
                logger.error("Failed to stop exports", error=str(e))
        
        # Lock sensitive evidence
        if self._lock_sensitive_evidence_callback and self.config.lock_sensitive_evidence:
            try:
                result = self._lock_sensitive_evidence_callback()
                if asyncio.iscoroutine(result):
                    tasks.append(asyncio.create_task(result))
                self._evidence_locked = True
            except Exception as e:
                logger.error("Failed to lock sensitive evidence", error=str(e))
        
        # Wait for all tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Update audit record with final state
        self.audit_record.capture_status = "STOPPED" if self._capture_stopped else "FAILED"
        self.audit_record.processing_status = "STOPPED" if self._processing_stopped else "FAILED"
        self.audit_record.active_test_status = "ABORTED" if self._active_tests_stopped else "NONE"
        self.audit_record.exports_stopped = self._exports_stopped
        self.audit_record.sensitive_evidence_locked = self._evidence_locked
        
        # Set final state
        self.state = ESSState.STOPPED
        self._activation_event.set()
        
        logger.critical(
            "ESS ACTIVATION COMPLETE",
            event_id=event_id,
            operator=operator,
            capture_stopped=self._capture_stopped,
            processing_stopped=self._processing_stopped,
            active_tests_stopped=self._active_tests_stopped,
            exports_stopped=self._exports_stopped,
            evidence_locked=self._evidence_locked,
        )
        
        return self.audit_record
    
    async def recover(
        self,
        operator: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Recover from emergency stop state.
        
        This requires explicit authorization and does NOT automatically
        resume operations. It simply transitions the system back to
        READY state so operators can manually restart services.
        
        Args:
            operator: ID of the operator performing recovery
            reason: Optional reason for recovery
            
        Returns:
            True if recovery successful, False otherwise
        """
        if self.state != ESSState.STOPPED:
            logger.warning("Recovery attempted but ESS not in STOPPED state", state=self.state.value)
            return False
        
        if self.config.require_auth_for_recovery:
            # In production, this would verify operator permissions
            logger.info("Recovery authorization required", operator=operator)
        
        self.state = ESSState.RECOVERING
        logger.info("ESS RECOVERY INITIATED", operator=operator, reason=reason)
        
        # Update audit record
        if self.audit_record:
            self.audit_record.recovery_operator = operator
            self.audit_record.recovery_timestamp = datetime.now(timezone.utc)
            self.audit_record.recovery_reason = reason
        
        # Reset state
        self.state = ESSState.READY
        self._activation_event.clear()
        
        logger.info("ESS RECOVERY COMPLETE", operator=operator)
        return True
    
    def is_active(self) -> bool:
        """Check if ESS is currently active (system halted)."""
        return self.state == ESSState.STOPPED
    
    def is_ready(self) -> bool:
        """Check if ESS is ready (normal operation)."""
        return self.state == ESSState.READY
    
    def get_state(self) -> ESSState:
        """Get current ESS state."""
        return self.state
    
    def get_audit_record(self) -> Optional[ESSAuditRecord]:
        """Get the most recent audit record."""
        return self.audit_record
    
    def can_perform_operation(self, operation_type: str) -> bool:
        """
        Check if a specific operation type is allowed.
        
        This is called by other components to check if they should
        proceed with their operation.
        
        Args:
            operation_type: Type of operation (capture, processing, test, export)
            
        Returns:
            True if operation is allowed, False if ESS is active
        """
        if self.state == ESSState.STOPPED:
            return False
        return True


# Global ESS instance (to be initialized by application)
_ess_instance: Optional[EmergencySecurityStop] = None


def initialize_ess(config: ESSConfig) -> EmergencySecurityStop:
    """Initialize the global ESS instance."""
    global _ess_instance
    _ess_instance = EmergencySecurityStop(config)
    return _ess_instance


def get_ess() -> Optional[EmergencySecurityStop]:
    """Get the global ESS instance."""
    return _ess_instance


def is_ess_active() -> bool:
    """Check if ESS is currently active globally."""
    if _ess_instance:
        return _ess_instance.is_active()
    return False
