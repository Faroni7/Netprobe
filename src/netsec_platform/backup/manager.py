"""
Backup Manager
Handles automated backups and restoration.
"""
import os
import tarfile
import time
import shutil

class BackupManager:
    def __init__(self, backup_dir: str = "./backups"):
        self.backup_dir = backup_dir
        os.makedirs(backup_dir, exist_ok=True)

    def create_backup(self, source_path: str) -> str:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        archive_name = f"backup_{timestamp}.tar.gz"
        archive_path = os.path.join(self.backup_dir, archive_name)
        
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
            
        return archive_name

    def restore_backup(self, archive_name: str, target_path: str):
        archive_path = os.path.join(self.backup_dir, archive_name)
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Backup {archive_name} not found")
            
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=target_path)
