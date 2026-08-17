"""
Packet Loss Monitor
Tracks network packet loss rates.
"""
class PacketLossMonitor:
    def __init__(self):
        self.sent = 0
        self.lost = 0

    def report_packet(self, success: bool):
        self.sent += 1
        if not success:
            self.lost += 1

    def get_loss_rate(self) -> float:
        if self.sent == 0:
            return 0.0
        return (self.lost / self.sent) * 100
