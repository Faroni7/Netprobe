"""
Database Connection Pool Manager
"""
class PoolManager:
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self.active_connections = 0

    def get_connection(self):
        if self.active_connections < self.max_connections:
            self.active_connections += 1
            return "ConnectionObject"
        raise Exception("Connection pool exhausted")

    def release_connection(self):
        if self.active_connections > 0:
            self.active_connections -= 1
