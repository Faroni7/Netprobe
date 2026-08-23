"""
BlackBox Recon - Security Headers Analysis Phase
Phase 6: Analyze HTTP security headers and identify missing controls
"""
import aiohttp
from typing import Dict, Any, List
from app.recon.base import BaseReconPhase
from app.config import settings


class SecurityHeadersPhase(BaseReconPhase):
    """Security Headers Analysis reconnaissance phase."""
    
    name = "security_headers"
    order = 6
    description = "Security header analysis and missing control detection"
    
    # Security headers to check with recommended values
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "recommended": "max-age=31536000; includeSubDomains",
            "severity": "medium",
            "description": "Enforces HTTPS connections"
        },
        "Content-Security-Policy": {
            "recommended": "default-src 'self'",
            "severity": "high",
            "description": "Prevents XSS and data injection attacks"
        },
        "X-Content-Type-Options": {
            "recommended": "nosniff",
            "severity": "low",
            "description": "Prevents MIME type sniffing"
        },
        "X-Frame-Options": {
            "recommended": "DENY or SAMEORIGIN",
            "severity": "medium",
            "description": "Prevents clickjacking attacks"
        },
        "X-XSS-Protection": {
            "recommended": "1; mode=block",
            "severity": "low",
            "description": "Legacy XSS filter (deprecated but still useful)"
        },
        "Referrer-Policy": {
            "recommended": "strict-origin-when-cross-origin",
            "severity": "low",
            "description": "Controls referrer information leakage"
        },
        "Permissions-Policy": {
            "recommended": "geolocation=(), microphone=(), camera=()",
            "severity": "low",
            "description": "Controls browser feature permissions"
        },
        "Cache-Control": {
            "recommended": "no-store, no-cache, must-revalidate",
            "severity": "low",
            "description": "Prevents caching of sensitive data"
        },
        "Pragma": {
            "recommended": "no-cache",
            "severity": "info",
            "description": "Legacy cache control for HTTP/1.0"
        }
    }
    
    async def execute(self) -> Dict[str, Any]:
        """Execute security headers analysis."""
        try:
            present_headers: List[Dict[str, Any]] = []
            missing_headers: List[Dict[str, Any]] = []
            issues: List[Dict[str, Any]] = []
            
            # Fetch the target to get headers
            headers = self._get_headers()
            timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)
            
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                try:
                    async with session.get(self.target_url) as response:
                        response_headers = dict(response.headers)
                        
                        # Check each security header
                        for header_name, header_info in self.SECURITY_HEADERS.items():
                            header_lower = header_name.lower()
                            
                            # Find header (case-insensitive)
                            found_value = None
                            for resp_header, resp_value in response_headers.items():
                                if resp_header.lower() == header_lower:
                                    found_value = resp_value
                                    break
                            
                            if found_value:
                                present_headers.append({
                                    "name": header_name,
                                    "value": found_value,
                                    "recommended": header_info["recommended"],
                                    "properly_configured": self._check_header_value(header_name, found_value)
                                })
                                
                                # Check if value is properly configured
                                if not self._check_header_value(header_name, found_value):
                                    issues.append({
                                        "header": header_name,
                                        "issue": "Improperly configured",
                                        "current_value": found_value,
                                        "recommended": header_info["recommended"],
                                        "severity": header_info["severity"]
                                    })
                                    self.add_finding(
                                        finding_type="misconfigured_header",
                                        title=f"Misconfigured Security Header: {header_name}",
                                        severity=header_info["severity"],
                                        description=f"{header_name} is present but may be misconfigured",
                                        evidence=f"Current: {found_value}, Recommended: {header_info['recommended']}",
                                        remediation=f"Set {header_name} to: {header_info['recommended']}"
                                    )
                            else:
                                missing_headers.append({
                                    "name": header_name,
                                    "severity": header_info["severity"],
                                    "description": header_info["description"],
                                    "recommended": header_info["recommended"]
                                })
                                issues.append({
                                    "header": header_name,
                                    "issue": "Missing",
                                    "severity": header_info["severity"],
                                    "recommended": header_info["recommended"]
                                })
                                self.add_finding(
                                    finding_type="missing_security_header",
                                    title=f"Missing Security Header: {header_name}",
                                    severity=header_info["severity"],
                                    description=header_info["description"],
                                    evidence=f"Header {header_name} not found in response",
                                    remediation=f"Add {header_name} header with value: {header_info['recommended']}"
                                )
                
                except Exception as e:
                    return {
                        "present_headers": [],
                        "missing_headers": [],
                        "issues": [{"error": str(e)}],
                        "status": "failed"
                    }
            
            # Calculate summary
            high_severity_missing = len([h for h in missing_headers if h["severity"] == "high"])
            medium_severity_missing = len([h for h in missing_headers if h["severity"] == "medium"])
            
            return {
                "present_headers": present_headers,
                "present_count": len(present_headers),
                "missing_headers": missing_headers,
                "missing_count": len(missing_headers),
                "issues": issues,
                "issue_count": len(issues),
                "high_severity_issues": high_severity_missing,
                "medium_severity_issues": medium_severity_missing,
                "security_score": self._calculate_security_score(present_headers, missing_headers),
                "status": "completed"
            }
            
        except Exception as e:
            return {
                "present_headers": [],
                "missing_headers": [],
                "issues": [],
                "status": "failed",
                "error": str(e)
            }
    
    def _check_header_value(self, header_name: str, value: str) -> bool:
        """Check if a header value is properly configured."""
        value_lower = value.lower()
        
        if header_name == "Strict-Transport-Security":
            return "max-age" in value_lower and int(''.join(filter(str.isdigit, value))) >= 31536000
        
        elif header_name == "Content-Security-Policy":
            return "default-src" in value_lower or "script-src" in value_lower
        
        elif header_name == "X-Content-Type-Options":
            return "nosniff" in value_lower
        
        elif header_name == "X-Frame-Options":
            return "deny" in value_lower or "sameorigin" in value_lower
        
        elif header_name == "X-XSS-Protection":
            return "1" in value
        
        elif header_name == "Referrer-Policy":
            valid_policies = ["no-referrer", "no-referrer-when-downgrade", "origin", 
                            "origin-when-cross-origin", "same-origin", "strict-origin",
                            "strict-origin-when-cross-origin", "unsafe-url"]
            return any(policy in value_lower for policy in valid_policies)
        
        elif header_name == "Permissions-Policy":
            return True  # Any value is better than none
        
        elif header_name == "Cache-Control":
            return "no-store" in value_lower or "no-cache" in value_lower
        
        elif header_name == "Pragma":
            return "no-cache" in value_lower
        
        return True
    
    def _calculate_security_score(self, present: List, missing: List) -> int:
        """Calculate a simple security score (0-100)."""
        if not self.SECURITY_HEADERS:
            return 0
        
        total_headers = len(self.SECURITY_HEADERS)
        present_count = len(present)
        
        # Weight by severity
        severity_weights = {"high": 3, "medium": 2, "low": 1, "info": 0.5}
        
        max_score = sum(severity_weights.get(h["severity"], 1) for h in self.SECURITY_HEADERS.values())
        current_score = sum(
            severity_weights.get(
                next((mh["severity"] for mh in missing if mh["name"] == ph["name"]), "low"),
                1
            ) for ph in present
        )
        
        if max_score == 0:
            return 0
        
        return min(100, int((current_score / max_score) * 100))
