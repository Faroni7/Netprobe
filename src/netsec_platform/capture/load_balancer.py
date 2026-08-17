"""
Capture Load Balancer
Distributes packet capture tasks.
"""
class CaptureLoadBalancer:
    def __init__(self):
        self.interfaces = []

    def add_interface(self, iface: str):
        self.interfaces.append(iface)

    def distribute_task(self, task):
        # Round robin logic
        return self.interfaces[0]
