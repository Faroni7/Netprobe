"""
Auto Scaler
Scales workers based on load.
"""
class AutoScaler:
    def __init__(self, min_workers: int = 2, max_workers: int = 10):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.current_workers = min_workers

    def scale_up(self):
        if self.current_workers < self.max_workers:
            self.current_workers += 1
            return True
        return False

    def scale_down(self):
        if self.current_workers > self.min_workers:
            self.current_workers -= 1
            return True
        return False
