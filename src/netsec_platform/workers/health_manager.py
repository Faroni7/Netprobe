"""
Worker Health Manager
Manages worker process health.
"""
class WorkerHealthManager:
    def __init__(self):
        self.workers = {}

    def register_worker(self, worker_id: str):
        self.workers[worker_id] = {"status": "active", "last_heartbeat": time.time()}

    def heartbeat(self, worker_id: str):
        if worker_id in self.workers:
            self.workers[worker_id]["last_heartbeat"] = time.time()
