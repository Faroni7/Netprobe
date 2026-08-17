"""
Session Management Module
Handles secure session creation, validation, and concurrency limits.
"""
import uuid
import time
from typing import Dict, Optional

class SessionManager:
    def __init__(self, max_concurrent_sessions: int = 3):
        self.sessions: Dict[str, dict] = {}
        self.user_sessions: Dict[str, list] = {}
        self.max_concurrent = max_concurrent_sessions

    def create_session(self, user_id: str, ip_address: str) -> str:
        # Enforce concurrency limit
        active_sessions = self.user_sessions.get(user_id, [])
        if len(active_sessions) >= self.max_concurrent:
            # Kill oldest session
            oldest = active_sessions.pop(0)
            del self.sessions[oldest]
        
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "user_id": user_id,
            "ip": ip_address,
            "created_at": time.time(),
            "last_activity": time.time()
        }
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)
        
        return session_id

    def validate_session(self, session_id: str) -> Optional[dict]:
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Check expiration (e.g., 24 hours)
        if time.time() - session["last_activity"] > 86400:
            self.destroy_session(session_id)
            return None
            
        session["last_activity"] = time.time()
        return session

    def destroy_session(self, session_id: str):
        if session_id in self.sessions:
            user_id = self.sessions[session_id]["user_id"]
            del self.sessions[session_id]
            if user_id in self.user_sessions:
                self.user_sessions[user_id].remove(session_id)
