"""
Session Concurrency Management

Enforces limits on concurrent sessions per user and provides
session tracking with remote termination capabilities.
"""

from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import hashlib


@dataclass
class SessionInfo:
    """Information about an active session"""
    session_id: str
    user_id: str
    ip_address: str
    user_agent: str
    login_time: datetime
    last_activity: datetime
    device_fingerprint: Optional[str] = None
    is_active: bool = True
    
    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "login_time": self.login_time.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "device_fingerprint": self.device_fingerprint,
            "is_active": self.is_active
        }


class SessionConcurrencyManager:
    """Manage concurrent session limits per user"""
    
    def __init__(self, max_sessions_per_user: int = 3):
        self.max_sessions = max_sessions_per_user
        self.sessions: Dict[str, SessionInfo] = {}  # session_id -> SessionInfo
        self.user_sessions: Dict[str, Set[str]] = {}  # user_id -> set of session_ids
    
    def register_session(self, session_info: SessionInfo) -> tuple[bool, Optional[str]]:
        """
        Register a new session, enforcing concurrency limits
        
        Returns:
            Tuple of (success, rejected_reason)
        """
        user_id = session_info.user_id
        current_sessions = self.user_sessions.get(user_id, set())
        
        # Check if limit reached
        if len(current_sessions) >= self.max_sessions:
            return False, f"Maximum concurrent sessions ({self.max_sessions}) reached"
        
        # Register session
        self.sessions[session_info.session_id] = session_info
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = set()
        self.user_sessions[user_id].add(session_info.session_id)
        
        return True, None
    
    def get_user_sessions(self, user_id: str) -> List[SessionInfo]:
        """Get all active sessions for a user"""
        session_ids = self.user_sessions.get(user_id, set())
        return [
            self.sessions[sid] 
            for sid in session_ids 
            if sid in self.sessions and self.sessions[sid].is_active
        ]
    
    def terminate_session(self, session_id: str, requester_user_id: str) -> bool:
        """Terminate a specific session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        # Only allow users to terminate their own sessions (or admins via separate check)
        if session.user_id != requester_user_id:
            return False
        
        session.is_active = False
        self.user_sessions[session.user_id].discard(session_id)
        return True
    
    def terminate_all_other_sessions(self, user_id: str, keep_session_id: str) -> int:
        """Terminate all sessions except one"""
        terminated = 0
        session_ids = list(self.user_sessions.get(user_id, set()))
        
        for session_id in session_ids:
            if session_id != keep_session_id:
                if self.terminate_session(session_id, user_id):
                    terminated += 1
        
        return terminated
    
    def update_activity(self, session_id: str) -> None:
        """Update last activity time for a session"""
        if session_id in self.sessions:
            self.sessions[session_id].last_activity = datetime.utcnow()
    
    def cleanup_stale_sessions(self, max_idle_minutes: int = 60) -> int:
        """Remove sessions that have been idle too long"""
        cutoff = datetime.utcnow() - timedelta(minutes=max_idle_minutes)
        stale = []
        
        for session_id, session in self.sessions.items():
            if session.last_activity < cutoff:
                stale.append(session_id)
        
        for session_id in stale:
            session = self.sessions[session_id]
            session.is_active = False
            self.user_sessions[session.user_id].discard(session_id)
        
        return len(stale)
    
    def get_concurrent_count(self, user_id: str) -> int:
        """Get current number of active sessions for a user"""
        return len(self.get_user_sessions(user_id))


# Global instance (to be replaced with database-backed storage in production)
session_manager = SessionConcurrencyManager()


def generate_device_fingerprint(user_agent: str, ip_prefix: str) -> str:
    """Generate a simple device fingerprint"""
    data = f"{user_agent}:{ip_prefix}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]
