"""
Health Check Module
Monitors system components status.
"""
import psutil
import time

class HealthMonitor:
    def check_cpu(self) -> float:
        return psutil.cpu_percent(interval=1)

    def check_memory(self) -> float:
        return psutil.virtual_memory().percent

    def check_disk(self) -> float:
        return psutil.disk_usage('/').percent

    def get_status(self) -> dict:
        return {
            "cpu": self.check_cpu(),
            "memory": self.check_memory(),
            "disk": self.check_disk(),
            "timestamp": time.time(),
            "status": "healthy" if self.check_cpu() < 90 else "warning"
        }
