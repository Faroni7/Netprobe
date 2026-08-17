"""
Verification Scheduler
Periodically checks integrity of stored evidence.
"""
import time
import threading
from typing import Callable

class VerificationScheduler:
    def __init__(self, store):
        self.store = store
        self.running = False
        self.interval = 3600  # 1 hour default

    def start(self, interval: int = 3600):
        self.interval = interval
        self.running = True
        thread = threading.Thread(target=self._run_loop, daemon=True)
        thread.start()

    def _run_loop(self):
        while self.running:
            time.sleep(self.interval)
            self.run_verification()

    def run_verification(self):
        print(f"[{time.time()}] Starting scheduled verification...")
        failed_count = 0
        for eid in self.store.manifest["files"]:
            if not self.store.verify_evidence(eid):
                print(f"ALERT: Integrity check failed for {eid}")
                failed_count += 1
        print(f"Verification complete. Failures: {failed_count}")
