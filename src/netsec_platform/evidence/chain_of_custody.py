"""
Chain of Custody Module
Immutable logging of evidence handling.
"""
import hashlib
import time
import json

class ChainOfCustody:
    def __init__(self):
        self.logs = []
        self.last_hash = "GENESIS"

    def add_entry(self, action: str, actor: str, evidence_id: str, details: str = ""):
        timestamp = time.time()
        entry_data = f"{self.last_hash}{action}{actor}{evidence_id}{details}{timestamp}"
        current_hash = hashlib.sha256(entry_data.encode()).hexdigest()
        
        entry = {
            "sequence": len(self.logs) + 1,
            "timestamp": timestamp,
            "action": action,
            "actor": actor,
            "evidence_id": evidence_id,
            "details": details,
            "previous_hash": self.last_hash,
            "current_hash": current_hash
        }
        
        self.logs.append(entry)
        self.last_hash = current_hash
        return entry

    def verify_integrity(self) -> bool:
        current_hash = "GENESIS"
        for entry in self.logs:
            if entry["previous_hash"] != current_hash:
                return False
            # Recalculate hash
            entry_data = f"{entry['previous_hash']}{entry['action']}{entry['actor']}{entry['evidence_id']}{entry['details']}{entry['timestamp']}"
            calculated_hash = hashlib.sha256(entry_data.encode()).hexdigest()
            if calculated_hash != entry["current_hash"]:
                return False
            current_hash = entry["current_hash"]
        return True
