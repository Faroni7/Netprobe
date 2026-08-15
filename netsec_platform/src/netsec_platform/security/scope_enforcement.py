"""
Pentest Scope Enforcement Middleware

This middleware ensures that all controlled testing operations are validated
against the authorized scope before execution. This is a CRITICAL security control
that prevents testing against unauthorized targets.

Security Boundary: Server-side enforcement that cannot be bypassed by frontend.
"""

from fastapi import HTTPException, status
from typing import List, Optional, Set
import ipaddress
from datetime import datetime
import re


class ScopeValidator:
    """
    Validates targets against authorized scope for pentesting operations.
    
    All methods return True if the target is within scope, False otherwise.
    Raises HTTPException for critical violations.
    """
    
    def __init__(self, allowed_domains: List[str], allowed_cidrs: List[str], 
                 excluded_domains: List[str], excluded_cidrs: List[str]):
        self.allowed_domains = set(d.lower() for d in allowed_domains)
        self.excluded_domains = set(d.lower() for d in excluded_domains)
        self.allowed_cidrs = self._parse_cidrs(allowed_cidrs)
        self.excluded_cidrs = self._parse_cidrs(excluded_cidrs)
    
    def _parse_cidrs(self, cidr_list: List[str]) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse CIDR strings into network objects."""
        networks = set()
        for cidr in cidr_list:
            try:
                networks.add(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                # Skip invalid CIDRs - should be caught during config validation
                pass
        return networks
    
    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is within authorized scope."""
        domain_lower = domain.lower()
        
        # Check exclusions first (exclusions take precedence)
        for excluded in self.excluded_domains:
            if domain_lower == excluded or domain_lower.endswith(f'.{excluded}'):
                return False
        
        # Check if domain matches any allowed domain
        for allowed in self.allowed_domains:
            if domain_lower == allowed or domain_lower.endswith(f'.{allowed}'):
                return True
        
        # Check wildcard patterns (e.g., *.example.com)
        for allowed in self.allowed_domains:
            if allowed.startswith('*.'):
                base_domain = allowed[2:]
                if domain_lower.endswith(base_domain):
                    return True
        
        return False
    
    def is_ip_in_scope(self, ip_str: str) -> bool:
        """Check if an IP address is within authorized scope."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        
        # Check exclusions first
        for excluded_net in self.excluded_cidrs:
            if ip in excluded_net:
                return False
        
        # Check if IP is in any allowed network
        for allowed_net in self.allowed_cidrs:
            if ip in allowed_net:
                return True
        
        return False
    
    def validate_target(self, target: str, target_type: str = 'auto') -> bool:
        """
        Validate a target (domain or IP) against scope.
        
        Args:
            target: The target to validate (domain name or IP address)
            target_type: 'domain', 'ip', or 'auto' for automatic detection
            
        Returns:
            True if target is within scope
            
        Raises:
            HTTPException: If target is out of scope
        """
        # Auto-detect target type
        if target_type == 'auto':
            try:
                ipaddress.ip_address(target)
                target_type = 'ip'
            except ValueError:
                target_type = 'domain'
        
        if target_type == 'ip':
            if not self.is_ip_in_scope(target):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "TARGET_OUT_OF_SCOPE",
                        "message": f"Target IP {target} is not within authorized scope",
                        "target": target,
                        "target_type": "ip"
                    }
                )
            return True
        elif target_type == 'domain':
            if not self.is_domain_in_scope(target):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "TARGET_OUT_OF_SCOPE",
                        "message": f"Target domain {target} is not within authorized scope",
                        "target": target,
                        "target_type": "domain"
                    }
                )
            return True
        
        return False
    
    def validate_targets(self, targets: List[str]) -> dict:
        """
        Validate multiple targets at once.
        
        Returns:
            dict with 'valid', 'invalid', and 'errors' keys
        """
        valid = []
        invalid = []
        errors = []
        
        for target in targets:
            try:
                if self.validate_target(target):
                    valid.append(target)
            except HTTPException as e:
                invalid.append(target)
                errors.append(e.detail)
        
        return {
            "valid": valid,
            "invalid": invalid,
            "errors": errors,
            "all_valid": len(invalid) == 0
        }


def create_scope_validator(authorization_config: dict) -> ScopeValidator:
    """
    Create a scope validator from authorization configuration.
    
    Args:
        authorization_config: Dict containing scope configuration
        
    Returns:
        Configured ScopeValidator instance
    """
    return ScopeValidator(
        allowed_domains=authorization_config.get('allowed_domains', []),
        allowed_cidrs=authorization_config.get('allowed_cidrs', []),
        excluded_domains=authorization_config.get('excluded_domains', []),
        excluded_cidrs=authorization_config.get('excluded_cidrs', [])
    )


# ============================================================================
# FASTAPI DEPENDENCY FOR SCOPE VALIDATION
# ============================================================================

from fastapi import Depends, Request
from typing import Callable


def require_scope_validation(scope_validator: ScopeValidator):
    """
    FastAPI dependency that validates request targets against scope.
    
    Usage:
        @app.post("/api/tests/controlled")
        async def start_test(
            target: str,
            _: None = Depends(require_scope_validation(scope_validator))
        ):
            # Target is guaranteed to be in scope
            pass
    """
    async def validate_target_dependency(request: Request, target: str):
        scope_validator.validate_target(target)
        return target
    
    return validate_target_dependency


def validate_scope_middleware(scope_validator: ScopeValidator):
    """
    FastAPI middleware that validates pentest targets in request body.
    
    Automatically checks 'target' or 'targets' fields in JSON requests.
    """
    from fastapi import FastAPI
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    import json
    
    class ScopeValidationMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            # Only validate pentest-related endpoints
            if not request.url.path.startswith('/api/tests/'):
                return await call_next(request)
            
            # Skip non-POST requests
            if request.method != 'POST':
                return await call_next(request)
            
            # Read and parse body
            body = await request.body()
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return await call_next(request)
            
            # Validate single target
            if 'target' in data:
                scope_validator.validate_target(data['target'])
            
            # Validate multiple targets
            if 'targets' in data:
                result = scope_validator.validate_targets(data['targets'])
                if not result['all_valid']:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail={
                            "error": "SCOPE_VIOLATION",
                            "message": "One or more targets are outside authorized scope",
                            "invalid_targets": result['invalid']
                        }
                    )
            
            return await call_next(request)
    
    return ScopeValidationMiddleware
