"""
Scope Enforcement Module
Ensures pentest activities remain within authorized targets.
"""
import ipaddress
from typing import List, Set

class ScopeEnforcer:
    def __init__(self, allowed_targets: List[str]):
        self.allowed_networks = []
        for target in allowed_targets:
            try:
                if '/' in target:
                    self.allowed_networks.append(ipaddress.ip_network(target, strict=False))
                else:
                    self.allowed_networks.append(ipaddress.ip_network(f"{target}/32", strict=False))
            except ValueError:
                raise ValueError(f"Invalid target format: {target}")

    def is_target_allowed(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in self.allowed_networks)
        except ValueError:
            return False

    def validate_scan_request(self, targets: List[str]) -> dict:
        results = {"allowed": [], "blocked": []}
        for target in targets:
            if self.is_target_allowed(target):
                results["allowed"].append(target)
            else:
                results["blocked"].append(target)
        
        if results["blocked"]:
            raise PermissionError(f"Scan blocked for unauthorized targets: {results['blocked']}")
        
        return results
