"""
Security Detection Engine.

Configurable rule-based security detection system.
Detects security issues, misconfigurations, and potential threats.
"""

import logging
import re
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

from netsec_platform.models.core_models import (
    SecurityFinding,
    FindingSeverity,
    FindingStatus,
    FindingConfidence,
    NetworkFlow,
    EncryptionState,
    SecurityQuality,
    SensitiveArtifact,
    DNSQuery,
    TLSConnection,
)


logger = logging.getLogger(__name__)


class RuleCategory(str, Enum):
    """Categories of security rules."""
    CREDENTIAL_EXPOSURE = "credential_exposure"
    ENCRYPTION = "encryption"
    COOKIE_SECURITY = "cookie_security"
    SESSION_SECURITY = "session_security"
    DNS_ANOMALY = "dns_anomaly"
    TLS_WEAKNESS = "tls_weakness"
    DATA_EXPOSURE = "data_exposure"
    NETWORK_ANOMALY = "network_anomaly"


@dataclass
class SecurityRule:
    """
    Security detection rule.
    
    Rules define conditions for detecting security issues.
    """
    rule_id: str
    name: str
    category: RuleCategory
    severity: FindingSeverity
    description: str
    remediation: str
    
    # Rule configuration
    enabled: bool = True
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    
    # Custom parameters
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "enabled": self.enabled,
            "description": self.description,
            "remediation": self.remediation,
        }


class DetectionEngine:
    """
    Security detection engine.
    
    Applies security rules to network data to identify:
    - Credential exposure
    - Weak encryption
    - Security misconfigurations
    - Suspicious patterns
    """
    
    def __init__(self):
        self._rules: Dict[str, SecurityRule] = {}
        self._findings: List[SecurityFinding] = []
        self._custom_detectors: List[Callable] = []
        
        # Initialize default rules
        self._load_default_rules()
        
        logger.info("DetectionEngine initialized")
    
    def _load_default_rules(self):
        """Load default security detection rules."""
        default_rules = [
            SecurityRule(
                rule_id="RULE-001",
                name="Plaintext Credential Exposure",
                category=RuleCategory.CREDENTIAL_EXPOSURE,
                severity=FindingSeverity.CRITICAL,
                description="Credentials transmitted over plaintext protocol",
                remediation="Enforce HTTPS and prevent authentication over plaintext protocols",
                parameters={"protocols": ["HTTP", "FTP", "TELNET"]},
            ),
            SecurityRule(
                rule_id="RULE-002",
                name="Weak TLS Version",
                category=RuleCategory.ENCRYPTION,
                severity=FindingSeverity.HIGH,
                description="Deprecated TLS version detected",
                remediation="Upgrade to TLS 1.2 or higher",
                parameters={"min_version": "TLS 1.2"},
            ),
            SecurityRule(
                rule_id="RULE-003",
                name="Missing Secure Cookie Flag",
                category=RuleCategory.COOKIE_SECURITY,
                severity=FindingSeverity.MEDIUM,
                description="Authentication cookie missing Secure flag",
                remediation="Set Secure flag on all authentication cookies",
                parameters={},
            ),
            SecurityRule(
                rule_id="RULE-004",
                name="Missing HttpOnly Cookie Flag",
                category=RuleCategory.COOKIE_SECURITY,
                severity=FindingSeverity.MEDIUM,
                description="Authentication cookie missing HttpOnly flag",
                remediation="Set HttpOnly flag on session cookies",
                parameters={},
            ),
            SecurityRule(
                rule_id="RULE-005",
                name="Session Token in URL",
                category=RuleCategory.SESSION_SECURITY,
                severity=FindingSeverity.HIGH,
                description="Session identifier exposed in URL",
                remediation="Use cookies or headers for session management",
                parameters={},
            ),
            SecurityRule(
                rule_id="RULE-006",
                name="Expired Certificate",
                category=RuleCategory.TLS_WEAKNESS,
                severity=FindingSeverity.HIGH,
                description="TLS certificate has expired",
                remediation="Renew the TLS certificate",
                parameters={},
            ),
            SecurityRule(
                rule_id="RULE-007",
                name="NXDOMAIN Spike",
                category=RuleCategory.DNS_ANOMALY,
                severity=FindingSeverity.MEDIUM,
                description="Unusual number of NXDOMAIN responses",
                remediation="Investigate potential DGA or misconfiguration",
                parameters={"threshold": 0.3},
            ),
            SecurityRule(
                rule_id="RULE-008",
                name="Sensitive Data in HTTP",
                category=RuleCategory.DATA_EXPOSURE,
                severity=FindingSeverity.CRITICAL,
                description="Sensitive data transmitted over HTTP",
                remediation="Encrypt sensitive data transmission",
                parameters={},
            ),
        ]
        
        for rule in default_rules:
            self._rules[rule.rule_id] = rule
        
        logger.info(f"Loaded {len(default_rules)} default rules")
    
    def register_rule(self, rule: SecurityRule):
        """Register a security rule."""
        self._rules[rule.rule_id] = rule
        logger.debug(f"Registered rule {rule.rule_id}")
    
    def unregister_rule(self, rule_id: str):
        """Unregister a security rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.debug(f"Unregistered rule {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True
    
    def disable_rule(self, rule_id: str):
        """Disable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False
    
    def get_rules(self) -> List[SecurityRule]:
        """Get all registered rules."""
        return list(self._rules.values())
    
    def get_enabled_rules(self) -> List[SecurityRule]:
        """Get all enabled rules."""
        return [r for r in self._rules.values() if r.enabled]
    
    def evaluate_sensitive_artifact(
        self,
        artifact: SensitiveArtifact,
    ) -> List[SecurityFinding]:
        """Evaluate a sensitive artifact against rules."""
        findings = []
        
        # Check for plaintext credential exposure
        if artifact.transport_encryption == EncryptionState.PLAINTEXT:
            if artifact.artifact_type.value in [
                "password", "basic_auth", "bearer_token",
                "session_cookie", "auth_cookie",
            ]:
                rule = self._rules.get("RULE-001")
                if rule and rule.enabled:
                    finding = SecurityFinding(
                        finding_id=f"finding-{uuid4().hex[:8]}",
                        title=rule.name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        status=FindingStatus.NEW,
                        description=rule.description,
                        explanation=f"{artifact.artifact_type.value} transmitted over plaintext HTTP",
                        remediation=rule.remediation,
                        src_ip=artifact.src_ip,
                        dst_ip=artifact.dst_ip,
                        protocol=artifact.protocol,
                        timestamp=artifact.timestamp,
                        evidence_ids=[artifact.artifact_id],
                        packet_references=[artifact.packet_id] if artifact.packet_id else [],
                        flow_id=artifact.flow_id,
                    )
                    findings.append(finding)
        
        # Check for session tokens in URLs
        if artifact.artifact_type.value in ["session_cookie", "access_token", "bearer_token"]:
            if artifact.url_path and any(
                token in artifact.url_path.lower()
                for token in ["session", "token", "auth", "sid"]
            ):
                rule = self._rules.get("RULE-005")
                if rule and rule.enabled:
                    finding = SecurityFinding(
                        finding_id=f"finding-{uuid4().hex[:8]}",
                        title=rule.name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        status=FindingStatus.NEW,
                        description=rule.description,
                        explanation=f"Session artifact found in URL path: {artifact.url_path}",
                        remediation=rule.remediation,
                        src_ip=artifact.src_ip,
                        dst_ip=artifact.dst_ip,
                        protocol=artifact.protocol,
                        timestamp=artifact.timestamp,
                        evidence_ids=[artifact.artifact_id],
                    )
                    findings.append(finding)
        
        return findings
    
    def evaluate_flow(self, flow: NetworkFlow) -> List[SecurityFinding]:
        """Evaluate a network flow against rules."""
        findings = []
        
        # Check for weak/insecure flows
        if flow.security_quality == SecurityQuality.INSECURE:
            # This is informational - actual findings come from artifacts
            pass
        
        return findings
    
    def evaluate_tls_connection(
        self,
        tls_info: Dict[str, Any],
    ) -> List[SecurityFinding]:
        """Evaluate TLS connection against rules."""
        findings = []
        
        version = tls_info.get("version", "")
        
        # Check for deprecated TLS versions
        if "TLS 1.0" in version or "SSL" in version:
            rule = self._rules.get("RULE-002")
            if rule and rule.enabled:
                finding = SecurityFinding(
                    finding_id=f"finding-{uuid4().hex[:8]}",
                    title=rule.name,
                    severity=rule.severity,
                    confidence=FindingConfidence.HIGH,
                    status=FindingStatus.NEW,
                    description=rule.description,
                    explanation=f"Deprecated TLS version observed: {version}",
                    remediation=rule.remediation,
                    timestamp=datetime.now(timezone.utc),
                )
                findings.append(finding)
        elif "TLS 1.1" in version:
            rule = self._rules.get("RULE-002")
            if rule and rule.enabled:
                finding = SecurityFinding(
                    finding_id=f"finding-{uuid4().hex[:8]}",
                    title=rule.name,
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    status=FindingStatus.NEW,
                    description="TLS 1.1 is deprecated",
                    explanation=f"TLS 1.1 observed: {version}",
                    remediation="Upgrade to TLS 1.2 or higher",
                    timestamp=datetime.now(timezone.utc),
                )
                findings.append(finding)
        
        return findings
    
    def evaluate_dns_queries(
        self,
        queries: List[DNSQuery],
    ) -> List[SecurityFinding]:
        """Evaluate DNS queries for anomalies."""
        findings = []
        
        if len(queries) < 10:
            return findings
        
        # Count NXDOMAIN responses
        nxdomain_count = sum(1 for q in queries if q.response_code == "NXDOMAIN")
        nxdomain_rate = nxdomain_count / len(queries)
        
        rule = self._rules.get("RULE-007")
        threshold = rule.parameters.get("threshold", 0.3) if rule else 0.3
        
        if nxdomain_rate > threshold:
            if rule and rule.enabled:
                finding = SecurityFinding(
                    finding_id=f"finding-{uuid4().hex[:8]}",
                    title=rule.name,
                    severity=rule.severity,
                    confidence=FindingConfidence.MEDIUM,
                    status=FindingStatus.NEW,
                    description=f"NXDOMAIN rate: {nxdomain_rate:.1%}",
                    explanation=f"{nxdomain_count} NXDOMAIN responses out of {len(queries)} queries",
                    remediation=rule.remediation,
                    timestamp=datetime.now(timezone.utc),
                )
                findings.append(finding)
        
        return findings
    
    def add_finding(self, finding: SecurityFinding):
        """Add a security finding."""
        self._findings.append(finding)
        logger.info(f"Added finding: {finding.finding_id} - {finding.title}")
    
    def get_findings(
        self,
        severity: Optional[FindingSeverity] = None,
        status: Optional[FindingStatus] = None,
        limit: int = 100,
    ) -> List[SecurityFinding]:
        """Get security findings with optional filtering."""
        filtered = self._findings
        
        if severity:
            filtered = [f for f in filtered if f.severity == severity]
        
        if status:
            filtered = [f for f in filtered if f.status == status]
        
        return filtered[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection engine statistics."""
        severity_counts = {}
        for finding in self._findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "total_rules": len(self._rules),
            "enabled_rules": len(self.get_enabled_rules()),
            "total_findings": len(self._findings),
            "findings_by_severity": severity_counts,
        }
    
    def clear_findings(self):
        """Clear all findings."""
        self._findings.clear()
        logger.info("Cleared all findings")
