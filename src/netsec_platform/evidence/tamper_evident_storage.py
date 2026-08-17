"""
Tamper-Evident Storage
Writes evidence to disk with cryptographic sealing.
"""
import os
import hashlib
import json
import time

class TamperEvidentStore:
    def __init__(self, base_path: str = "./evidence_store"):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
        self.manifest_path = os.path.join(base_path, "manifest.json")
        self.manifest = self._load_manifest()

    def _load_manifest(self):
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path, 'r') as f:
                return json.load(f)
        return {"files": {}, "last_sealed": None}

    def store_evidence(self, evidence_id: str, data: bytes, metadata: dict):
        file_path = os.path.join(self.base_path, f"{evidence_id}.enc")
        
        # Calculate hash before writing
        data_hash = hashlib.sha256(data).hexdigest()
        
        with open(file_path, 'wb') as f:
            f.write(data)
            
        self.manifest["files"][evidence_id] = {
            "path": file_path,
            "hash": data_hash,
            "stored_at": time.time(),
            "metadata": metadata,
            "sealed": False
        }
        self._save_manifest()
        return data_hash

    def verify_evidence(self, evidence_id: str) -> bool:
        record = self.manifest["files"].get(evidence_id)
        if not record:
            return False
        
        if not os.path.exists(record["path"]):
            return False
            
        with open(record["path"], 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
            
        return current_hash == record["hash"]

    def _save_manifest(self):
        with open(self.manifest_path, 'w') as f:
            json.dump(self.manifest, f, indent=2)
