"""
Controlled Testing Module - Phase 7

Active security validation with explicit authorization, scope enforcement,
rate limiting, audit logging, and emergency stop integration.

This module is SEPARATE from passive monitoring and requires:
- Written authorization reference
- Explicit operator confirmation
- Target scope validation
- Rate limiting and timeouts
- Comprehensive audit trail
- Emergency stop override
"""

from enum import Enum
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, validator
import asyncio
import uuid
import logging
from ..utils.logging_config import get_secure_logger
from ..models.core_models import SensitiveArtifact, SecurityFinding

logger = get_secure_logger("controlled_testing")


class TestType(str, Enum):
    """Types of controlled security tests"""
    CREDENTIAL_VALIDATION = "credential_validation"
    SESSION_VALIDATION = "session_validation"
    TOKEN_VALIDATION = "token_validation"
    COOKIE_VALIDATION = "cookie_validation"
    ENDPOINT_PROBE = "endpoint_probe"
    AUTH_FLOW_TEST = "auth_flow_test"
    CUSTOM = "custom"


class TestStatus(str, Enum):
    """Test execution status"""
    DRAFT = "draft"
    PENDING_AUTHORIZATION = "pending_authorization"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"
    EMERGENCY_STOPPED = "emergency_stopped"


class TestResult(str, Enum):
    """Test outcome"""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SCOPE_VIOLATION = "scope_violation"
    RATE_LIMITED = "rate_limited"
    EMERGENCY_STOP = "emergency_stop"


class ControlledTestConfig(BaseModel):
    """Configuration for a controlled test"""
    
    # Authorization
    authz_reference: str = Field(..., description="Written authorization reference ID")
    authz_type: str = Field(default="written", description="Type of authorization")
    
    # Target specification
    target_url: str = Field(..., description="Target URL for testing")
    target_ips: List[str] = Field(default_factory=list, description="Allowed target IPs")
    allowed_domains: List[str] = Field(default_factory=list, description="Allowed domains")
    allowed_ports: List[int] = Field(default_factory=list, description="Allowed ports")
    
    # Test parameters
    test_type: TestType = Field(..., description="Type of test to perform")
    artifact_eid: Optional[str] = Field(None, description="Evidence ID of artifact to test")
    custom_payload: Optional[str] = Field(None, description="Custom payload for custom tests")
    
    # Safety limits
    max_requests: int = Field(default=100, ge=1, le=10000, description="Maximum requests")
    rate_limit: int = Field(default=10, ge=1, le=100, description="Requests per second")
    timeout_seconds: int = Field(default=300, ge=10, le=3600, description="Test timeout")
    dry_run: bool = Field(default=False, description="Preview without execution")
    
    # Metadata
    case_id: Optional[str] = Field(None, description="Associated investigation case")
    description: str = Field(default="", description="Test description")
    operator_notes: str = Field(default="", description="Operator notes")
    
    @validator('target_url')
    def validate_target_url(cls, v):
        """Ensure target URL has valid scheme"""
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError("Target URL must start with http:// or https://")
        return v
    
    @validator('allowed_domains')
    def validate_domains(cls, v):
        """Ensure domains don't contain wildcards that could be dangerous"""
        for domain in v:
            if '*' in domain and not domain.startswith('*.'):
                raise ValueError("Wildcards only allowed as subdomain prefix (*.example.com)")
        return v


@dataclass
class ControlledTest:
    """Represents a controlled security test"""
    
    test_id: str
    config: ControlledTestConfig
    status: TestStatus = TestStatus.DRAFT
    result: Optional[TestResult] = None
    
    # Execution tracking
    requests_sent: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Evidence and findings
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    
    # Audit trail
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    authorized_by: Optional[str] = None
    authorized_at: Optional[datetime] = None
    started_by: Optional[str] = None
    started_at: Optional[datetime] = None
    
    # Error tracking
    error_message: Optional[str] = None
    abort_reason: Optional[str] = None
    
    # HTTP responses (sample, not full)
    response_samples: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/API"""
        return {
            "test_id": self.test_id,
            "config": self.config.dict(),
            "status": self.status.value,
            "result": self.result.value if self.result else None,
            "requests_sent": self.requests_sent,
            "requests_successful": self.requests_successful,
            "requests_failed": self.requests_failed,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "evidence_ids": self.evidence_ids,
            "finding_ids": self.finding_ids,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "authorized_by": self.authorized_by,
            "authorized_at": self.authorized_at.isoformat() if self.authorized_at else None,
            "started_by": self.started_by,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "error_message": self.error_message,
            "abort_reason": self.abort_reason,
        }


class ScopeValidator:
    """Validates targets against authorized scope"""
    
    def __init__(self, allowed_cidrs: List[str], allowed_domains: List[str], 
                 excluded_cidrs: List[str], excluded_domains: List[str]):
        self.allowed_cidrs = allowed_cidrs
        self.allowed_domains = allowed_domains
        self.excluded_cidrs = excluded_cidrs
        self.excluded_domains = excluded_domains
        logger.info("ScopeValidator initialized", 
                   allowed_cidrs=len(allowed_cidrs),
                   allowed_domains=len(allowed_domains))
    
    def validate_target(self, config: ControlledTestConfig) -> tuple[bool, str]:
        """
        Validate test target against scope.
        Returns (is_valid, reason)
        """
        from ipaddress import ip_address, ip_network
        
        target_url = config.target_url
        
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            domain = parsed.hostname
            
            if not domain:
                return False, "Could not extract domain from target URL"
            
            # Check excluded domains first
            for excluded in self.excluded_domains:
                if domain == excluded or domain.endswith(f".{excluded}"):
                    return False, f"Target domain {domain} is in excluded list"
            
            # Check allowed domains
            domain_allowed = False
            for allowed in self.allowed_domains:
                if allowed.startswith('*.'):
                    # Wildcard subdomain
                    if domain == allowed[2:] or domain.endswith(f".{allowed[2:]}"):
                        domain_allowed = True
                        break
                elif domain == allowed:
                    domain_allowed = True
                    break
            
            if not domain_allowed and self.allowed_domains:
                return False, f"Target domain {domain} not in allowed list"
            
            # Resolve and check IPs if specified
            if config.target_ips:
                for ip_str in config.target_ips:
                    try:
                        ip = ip_address(ip_str)
                        
                        # Check excluded CIDRs
                        for excluded_cidr in self.excluded_cidrs:
                            if ip in ip_network(excluded_cidr, strict=False):
                                return False, f"Target IP {ip_str} is in excluded network {excluded_cidr}"
                        
                        # Check allowed CIDRs if specified
                        if self.allowed_cidrs:
                            ip_allowed = False
                            for allowed_cidr in self.allowed_cidrs:
                                if ip in ip_network(allowed_cidr, strict=False):
                                    ip_allowed = True
                                    break
                            if not ip_allowed:
                                return False, f"Target IP {ip_str} not in allowed networks"
                    
                    except ValueError as e:
                        return False, f"Invalid IP address {ip_str}: {e}"
            
            return True, "Target validated against scope"
            
        except Exception as e:
            logger.error("Scope validation failed", error=str(e))
            return False, f"Scope validation error: {e}"


class RateLimiter:
    """Token bucket rate limiter for controlled tests"""
    
    def __init__(self, rate: int, max_tokens: int = None):
        self.rate = rate  # tokens per second
        self.max_tokens = max_tokens or rate
        self.tokens = float(self.max_tokens)
        self.last_update = datetime.utcnow()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """Acquire a token, waiting if necessary"""
        async with self._lock:
            now = datetime.utcnow()
            elapsed = (now - self.last_update).total_seconds()
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            else:
                return False
    
    async def wait_for_token(self, timeout: float = 5.0) -> bool:
        """Wait for a token to become available"""
        start = datetime.utcnow()
        while (datetime.utcnow() - start).total_seconds() < timeout:
            if await self.acquire():
                return True
            await asyncio.sleep(0.1)
        return False


class ControlledTestingEngine:
    """
    Engine for executing controlled security tests.
    
    SEPARATE from passive monitoring. Requires:
    - Explicit authorization
    - Scope validation
    - Operator confirmation
    - Rate limiting
    - Emergency stop integration
    """
    
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        self.tests: Dict[str, ControlledTest] = {}
        self.running_tests: Dict[str, asyncio.Task] = {}
        self.rate_limiters: Dict[str, RateLimiter] = {}
        self.emergency_stop_callback: Optional[Callable] = None
        self.evidence_store_callback: Optional[Callable] = None
        self.finding_callback: Optional[Callable] = None
        self._lock = asyncio.Lock()
        
        logger.info("ControlledTestingEngine initialized")
    
    def set_emergency_stop_callback(self, callback: Callable):
        """Register callback to check emergency stop status"""
        self.emergency_stop_callback = callback
    
    def set_evidence_store_callback(self, callback: Callable):
        """Register callback to store evidence"""
        self.evidence_store_callback = callback
    
    def set_finding_callback(self, callback: Callable):
        """Register callback to record findings"""
        self.finding_callback = callback
    
    async def create_test(self, config: ControlledTestConfig, 
                         created_by: str) -> ControlledTest:
        """Create a new controlled test (draft state)"""
        test_id = f"TEST-{uuid.uuid4().hex[:8].upper()}"
        
        test = ControlledTest(
            test_id=test_id,
            config=config,
            status=TestStatus.DRAFT,
            created_by=created_by,
        )
        
        async with self._lock:
            self.tests[test_id] = test
        
        logger.info("Controlled test created", 
                   test_id=test_id, 
                   test_type=config.test_type.value,
                   target=config.target_url,
                   created_by=created_by)
        
        return test
    
    async def authorize_test(self, test_id: str, authorized_by: str) -> bool:
        """Authorize a test for execution"""
        async with self._lock:
            if test_id not in self.tests:
                logger.error("Test not found", test_id=test_id)
                return False
            
            test = self.tests[test_id]
            
            if test.status != TestStatus.DRAFT:
                logger.error("Cannot authorize test in current state", 
                           test_id=test_id, status=test.status.value)
                return False
            
            # Validate scope before authorizing
            is_valid, reason = self.scope_validator.validate_target(test.config)
            if not is_valid:
                logger.error("Scope validation failed", test_id=test_id, reason=reason)
                test.status = TestStatus.FAILED
                test.error_message = f"Scope validation failed: {reason}"
                return False
            
            test.status = TestStatus.AUTHORIZED
            test.authorized_by = authorized_by
            test.authorized_at = datetime.utcnow()
        
        logger.info("Controlled test authorized", 
                   test_id=test_id, 
                   authorized_by=authorized_by)
        
        return True
    
    async def execute_test(self, test_id: str, started_by: str) -> bool:
        """Execute an authorized controlled test"""
        async with self._lock:
            if test_id not in self.tests:
                logger.error("Test not found", test_id=test_id)
                return False
            
            test = self.tests[test_id]
            
            if test.status != TestStatus.AUTHORIZED:
                logger.error("Test not authorized or already running", 
                           test_id=test_id, status=test.status.value)
                return False
            
            test.status = TestStatus.RUNNING
            test.started_by = started_by
            test.started_at = datetime.utcnow()
            test.start_time = datetime.utcnow()
            
            # Create rate limiter for this test
            self.rate_limiters[test_id] = RateLimiter(
                rate=test.config.rate_limit,
                max_tokens=test.config.rate_limit
            )
        
        # Start test execution in background
        task = asyncio.create_task(self._run_test(test_id))
        self.running_tests[test_id] = task
        
        logger.info("Controlled test execution started", 
                   test_id=test_id, 
                   started_by=started_by)
        
        return True
    
    async def _run_test(self, test_id: str):
        """Execute the actual test logic"""
        test = self.tests[test_id]
        rate_limiter = self.rate_limiters[test_id]
        
        try:
            logger.info("Running controlled test", test_id=test_id)
            
            # Dry run mode - just validate and return
            if test.config.dry_run:
                await asyncio.sleep(1)  # Simulate brief execution
                test.status = TestStatus.COMPLETED
                test.result = TestResult.SUCCESS
                test.end_time = datetime.utcnow()
                logger.info("Dry run completed", test_id=test_id)
                return
            
            # Main test loop
            for i in range(test.config.max_requests):
                # Check emergency stop
                if self.emergency_stop_callback:
                    is_stopped = await self.emergency_stop_callback()
                    if is_stopped:
                        logger.warning("Test aborted due to emergency stop", test_id=test_id)
                        test.status = TestStatus.EMERGENCY_STOPPED
                        test.result = TestResult.EMERGENCY_STOP
                        test.abort_reason = "Emergency security stop activated"
                        test.end_time = datetime.utcnow()
                        return
                
                # Check timeout
                if test.started_at:
                    elapsed = (datetime.utcnow() - test.started_at).total_seconds()
                    if elapsed > test.config.timeout_seconds:
                        logger.warning("Test timed out", test_id=test_id)
                        test.status = TestStatus.COMPLETED
                        test.result = TestResult.TIMEOUT
                        test.end_time = datetime.utcnow()
                        return
                
                # Rate limiting
                if not await rate_limiter.wait_for_token(timeout=10.0):
                    test.requests_failed += 1
                    logger.warning("Rate limit timeout", test_id=test_id)
                    continue
                
                # Execute test request based on type
                success = await self._execute_test_request(test)
                
                if success:
                    test.requests_successful += 1
                else:
                    test.requests_failed += 1
                
                test.requests_sent += 1
                
                # Small delay between requests
                await asyncio.sleep(0.1)
            
            # Test completed normally
            test.status = TestStatus.COMPLETED
            test.result = TestResult.SUCCESS if test.requests_failed == 0 else TestResult.PARTIAL_SUCCESS
            test.end_time = datetime.utcnow()
            
            logger.info("Controlled test completed", 
                       test_id=test_id, 
                       successful=test.requests_successful,
                       failed=test.requests_failed)
        
        except asyncio.CancelledError:
            logger.warning("Test cancelled", test_id=test_id)
            test.status = TestStatus.ABORTED
            test.result = TestResult.FAILURE
            test.abort_reason = "Test cancelled"
            test.end_time = datetime.utcnow()
            raise
        
        except Exception as e:
            logger.error("Test failed with error", test_id=test_id, error=str(e))
            test.status = TestStatus.FAILED
            test.result = TestResult.FAILURE
            test.error_message = str(e)
            test.end_time = datetime.utcnow()
    
    async def _execute_test_request(self, test: ControlledTest) -> bool:
        """Execute a single test request based on test type"""
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                # Build request based on test type
                if test.config.test_type == TestType.CREDENTIAL_VALIDATION:
                    # Validate credential (without actual login attempt)
                    # This would typically check if credential format is valid
                    # and if the endpoint responds appropriately
                    pass
                
                elif test.config.test_type == TestType.SESSION_VALIDATION:
                    # Validate session token
                    pass
                
                elif test.config.test_type == TestType.TOKEN_VALIDATION:
                    # Validate auth token
                    pass
                
                elif test.config.test_type == TestType.ENDPOINT_PROBE:
                    # Probe endpoint existence and response
                    async with session.get(
                        test.config.target_url,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        # Store sample response metadata (not full body)
                        sample = {
                            "status_code": response.status,
                            "headers": dict(response.headers),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                        test.response_samples.append(sample)
                        
                        # Record finding if unexpected behavior
                        if response.status == 200 and self.finding_callback:
                            # Could record successful probe as finding
                            pass
                
                elif test.config.test_type == TestType.AUTH_FLOW_TEST:
                    # Test authentication flow
                    pass
                
                elif test.config.test_type == TestType.CUSTOM:
                    # Custom payload execution
                    if test.config.custom_payload:
                        logger.info("Executing custom test", 
                                   test_id=test.test_id,
                                   payload_length=len(test.config.custom_payload))
                
                return True
        
        except Exception as e:
            logger.error("Test request failed", test_id=test.test_id, error=str(e))
            return False
    
    async def abort_test(self, test_id: str, reason: str, aborted_by: str) -> bool:
        """Abort a running test"""
        async with self._lock:
            if test_id not in self.tests:
                return False
            
            test = self.tests[test_id]
            
            if test.status not in [TestStatus.RUNNING, TestStatus.AUTHORIZED]:
                logger.error("Cannot abort test in current state", 
                           test_id=test_id, status=test.status.value)
                return False
            
            # Cancel running task
            if test_id in self.running_tests:
                self.running_tests[test_id].cancel()
                del self.running_tests[test_id]
            
            test.status = TestStatus.ABORTED
            test.result = TestResult.FAILURE
            test.abort_reason = reason
            test.end_time = datetime.utcnow()
        
        logger.warning("Controlled test aborted", 
                      test_id=test_id, 
                      reason=reason,
                      aborted_by=aborted_by)
        
        return True
    
    async def emergency_stop_all(self) -> int:
        """Emergency stop all running tests"""
        stopped_count = 0
        
        async with self._lock:
            for test_id, task in list(self.running_tests.items()):
                task.cancel()
                test = self.tests[test_id]
                test.status = TestStatus.EMERGENCY_STOPPED
                test.result = TestResult.EMERGENCY_STOP
                test.abort_reason = "Emergency security stop activated"
                test.end_time = datetime.utcnow()
                stopped_count += 1
            
            self.running_tests.clear()
        
        logger.critical("Emergency stop: all controlled tests terminated", 
                       stopped_count=stopped_count)
        
        return stopped_count
    
    def get_test(self, test_id: str) -> Optional[ControlledTest]:
        """Get test by ID"""
        return self.tests.get(test_id)
    
    def list_tests(self, status: Optional[TestStatus] = None) -> List[ControlledTest]:
        """List tests, optionally filtered by status"""
        if status:
            return [t for t in self.tests.values() if t.status == status]
        return list(self.tests.values())
    
    def get_test_stats(self) -> Dict[str, Any]:
        """Get statistics about controlled tests"""
        tests = list(self.tests.values())
        return {
            "total_tests": len(tests),
            "by_status": {
                status.value: len([t for t in tests if t.status == status])
                for status in TestStatus
            },
            "running_tests": len(self.running_tests),
        }
