"""
Tests for Controlled Testing Module - Phase 7

Tests for active security validation with explicit authorization.
"""

import pytest
import asyncio
from datetime import datetime
from netsec_platform.testing.controlled_testing import (
    TestType,
    TestStatus,
    TestResult,
    ControlledTestConfig,
    ControlledTest,
    ScopeValidator,
    RateLimiter,
    ControlledTestingEngine,
)


class TestControlledTestConfig:
    """Test controlled test configuration"""
    
    def test_create_valid_config(self):
        """Create valid test configuration"""
        config = ControlledTestConfig(
            authz_reference="AUTH-2026-001",
            target_url="https://test.example.com",
            test_type=TestType.ENDPOINT_PROBE,
            allowed_domains=["test.example.com"],
        )
        assert config.authz_reference == "AUTH-2026-001"
        assert config.target_url == "https://test.example.com"
        assert config.test_type == TestType.ENDPOINT_PROBE
        assert config.max_requests == 100
        assert config.rate_limit == 10
        assert config.dry_run is False
    
    def test_invalid_url_scheme(self):
        """Reject URLs without http/https scheme"""
        with pytest.raises(ValueError, match="must start with http"):
            ControlledTestConfig(
                authz_reference="AUTH-001",
                target_url="ftp://test.example.com",
                test_type=TestType.ENDPOINT_PROBE,
            )
    
    def test_dry_run_mode(self):
        """Enable dry run mode"""
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.example.com",
            test_type=TestType.ENDPOINT_PROBE,
            dry_run=True,
        )
        assert config.dry_run is True


class TestScopeValidator:
    """Test scope validation"""
    
    def test_valid_domain_in_scope(self):
        """Validate domain within allowed scope"""
        validator = ScopeValidator(
            allowed_cidrs=[],
            allowed_domains=["api.example.com", "test.com"],
            excluded_cidrs=[],
            excluded_domains=[],
        )
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://api.example.com/test",
            test_type=TestType.ENDPOINT_PROBE,
            allowed_domains=["api.example.com", "test.com"],
        )
        
        is_valid, reason = validator.validate_target(config)
        assert is_valid is True, f"Validation failed: {reason}"
    
    def test_wildcard_subdomain_match(self):
        """Match wildcard subdomain patterns"""
        validator = ScopeValidator(
            allowed_cidrs=[],
            allowed_domains=["*.example.com"],
            excluded_cidrs=[],
            excluded_domains=[],
        )
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://api.example.com/test",
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        is_valid, reason = validator.validate_target(config)
        assert is_valid is True
    
    def test_domain_not_in_scope(self):
        """Reject domain not in allowed list"""
        validator = ScopeValidator(
            allowed_cidrs=[],
            allowed_domains=["example.com"],
            excluded_cidrs=[],
            excluded_domains=[],
        )
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://evil.com/test",
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        is_valid, reason = validator.validate_target(config)
        assert is_valid is False
        assert "not in allowed list" in reason
    
    def test_excluded_domain(self):
        """Reject excluded domain"""
        validator = ScopeValidator(
            allowed_cidrs=[],
            allowed_domains=["*.example.com"],
            excluded_cidrs=[],
            excluded_domains=["internal.example.com"],
        )
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://internal.example.com/admin",
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        is_valid, reason = validator.validate_target(config)
        assert is_valid is False
        assert "excluded list" in reason
    
    def test_ip_in_allowed_cidr(self):
        """Validate IP within allowed CIDR"""
        validator = ScopeValidator(
            allowed_cidrs=["10.0.0.0/8"],
            allowed_domains=[],
            excluded_cidrs=[],
            excluded_domains=[],
        )
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://10.10.10.10/test",
            target_ips=["10.10.10.10"],
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        is_valid, reason = validator.validate_target(config)
        assert is_valid is True
    
    def test_ip_in_excluded_cidr(self):
        """Reject IP in excluded CIDR"""
        validator = ScopeValidator(
            allowed_cidrs=["10.0.0.0/8"],
            allowed_domains=[],
            excluded_cidrs=["10.10.50.0/24"],
            excluded_domains=[],
        )
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://10.10.50.5/test",
            target_ips=["10.10.50.5"],
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        is_valid, reason = validator.validate_target(config)
        assert is_valid is False
        assert "excluded network" in reason


class TestRateLimiter:
    """Test rate limiting"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_basic(self):
        """Basic rate limiter functionality"""
        limiter = RateLimiter(rate=10, max_tokens=10)
        
        # Should acquire token immediately
        result = await limiter.acquire()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_rate_limiter_exhaustion(self):
        """Rate limiter exhausts tokens"""
        limiter = RateLimiter(rate=1, max_tokens=2)
        
        # Exhaust tokens
        await limiter.acquire()
        await limiter.acquire()
        
        # Next should fail
        result = await limiter.acquire()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_rate_limiter_refill(self):
        """Tokens refill over time"""
        limiter = RateLimiter(rate=100, max_tokens=1)
        
        # Exhaust token
        await limiter.acquire()
        
        # Wait for refill
        await asyncio.sleep(0.02)
        
        # Should have token again
        result = await limiter.acquire()
        assert result is True


class TestControlledTestingEngine:
    """Test controlled testing engine"""
    
    @pytest.mark.asyncio
    async def test_create_test(self):
        """Create a new controlled test"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.com/api",
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        test = await engine.create_test(config, created_by="analyst01")
        
        assert test.test_id.startswith("TEST-")
        assert test.status == TestStatus.DRAFT
        assert test.created_by == "analyst01"
    
    @pytest.mark.asyncio
    async def test_authorize_test(self):
        """Authorize a test for execution"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.com/api",
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        test = await engine.create_test(config, created_by="analyst01")
        success = await engine.authorize_test(test.test_id, authorized_by="manager01")
        
        assert success is True
        assert test.status == TestStatus.AUTHORIZED
        assert test.authorized_by == "manager01"
    
    @pytest.mark.asyncio
    async def test_authorize_fails_scope_validation(self):
        """Authorization fails if scope validation fails"""
        validator = ScopeValidator([], ["allowed.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://forbidden.com/api",
            test_type=TestType.ENDPOINT_PROBE,
        )
        
        test = await engine.create_test(config, created_by="analyst01")
        success = await engine.authorize_test(test.test_id, authorized_by="manager01")
        
        assert success is False
        assert test.status == TestStatus.FAILED
        assert "scope validation" in test.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Execute test in dry run mode"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.com/api",
            test_type=TestType.ENDPOINT_PROBE,
            dry_run=True,
            max_requests=10,
        )
        
        test = await engine.create_test(config, created_by="analyst01")
        await engine.authorize_test(test.test_id, authorized_by="manager01")
        success = await engine.execute_test(test.test_id, started_by="analyst01")
        
        assert success is True
        
        # Wait for completion
        await asyncio.sleep(2)
        
        assert test.status == TestStatus.COMPLETED
        assert test.result == TestResult.SUCCESS
    
    @pytest.mark.asyncio
    async def test_emergency_stop_all(self):
        """Emergency stop terminates all running tests"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        # Create and start a long-running test
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.com/api",
            test_type=TestType.ENDPOINT_PROBE,
            max_requests=1000,
            timeout_seconds=300,
        )
        
        test = await engine.create_test(config, created_by="analyst01")
        await engine.authorize_test(test.test_id, authorized_by="manager01")
        await engine.execute_test(test.test_id, started_by="analyst01")
        
        # Give it time to start
        await asyncio.sleep(0.5)
        
        # Emergency stop
        stopped_count = await engine.emergency_stop_all()
        
        assert stopped_count >= 1
        assert test.status == TestStatus.EMERGENCY_STOPPED
        assert test.result == TestResult.EMERGENCY_STOP
        assert len(engine.running_tests) == 0
    
    @pytest.mark.asyncio
    async def test_abort_test(self):
        """Abort a specific test"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        config = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.com/api",
            test_type=TestType.ENDPOINT_PROBE,
            max_requests=1000,
        )
        
        test = await engine.create_test(config, created_by="analyst01")
        await engine.authorize_test(test.test_id, authorized_by="manager01")
        await engine.execute_test(test.test_id, started_by="analyst01")
        
        await asyncio.sleep(0.5)
        
        # Abort
        success = await engine.abort_test(
            test.test_id, 
            reason="Manual abort by operator",
            aborted_by="analyst01"
        )
        
        assert success is True
        assert test.status == TestStatus.ABORTED
        assert test.abort_reason == "Manual abort by operator"
    
    @pytest.mark.asyncio
    async def test_get_test_stats(self):
        """Get statistics about tests"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        # Create multiple tests
        for i in range(3):
            config = ControlledTestConfig(
                authz_reference=f"AUTH-00{i}",
                target_url="https://test.com/api",
                test_type=TestType.ENDPOINT_PROBE,
                dry_run=True,
            )
            await engine.create_test(config, created_by="analyst01")
        
        stats = engine.get_test_stats()
        
        assert stats["total_tests"] == 3
        assert "by_status" in stats
        assert "running_tests" in stats
    
    @pytest.mark.asyncio
    async def test_list_tests_by_status(self):
        """Filter tests by status"""
        validator = ScopeValidator([], ["test.com", "forbidden.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        # Create tests with different outcomes
        config1 = ControlledTestConfig(
            authz_reference="AUTH-001",
            target_url="https://test.com/api",
            test_type=TestType.ENDPOINT_PROBE,
            dry_run=True,
            allowed_domains=["test.com", "forbidden.com"],
        )
        test1 = await engine.create_test(config1, created_by="analyst01")
        
        config2 = ControlledTestConfig(
            authz_reference="AUTH-002",
            target_url="https://forbidden.com/api",
            test_type=TestType.ENDPOINT_PROBE,
            allowed_domains=["test.com", "forbidden.com"],
        )
        test2 = await engine.create_test(config2, created_by="analyst01")
        await engine.authorize_test(test2.test_id, authorized_by="manager01")
        
        # List draft tests
        draft_tests = engine.list_tests(status=TestStatus.DRAFT)
        assert len(draft_tests) >= 1, "Should have at least one draft test"
        
        # List authorized tests
        auth_tests = engine.list_tests(status=TestStatus.AUTHORIZED)
        assert len(auth_tests) >= 1, "Should have at least one authorized test"


class TestControlledTestLifecycle:
    """Test complete test lifecycle"""
    
    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """Test complete lifecycle: create → authorize → execute → complete"""
        validator = ScopeValidator([], ["test.com"], [], [])
        engine = ControlledTestingEngine(validator)
        
        # Set emergency stop callback (always returns False - no stop)
        async def check_ess():
            return False
        engine.set_emergency_stop_callback(check_ess)
        
        # Create test
        config = ControlledTestConfig(
            authz_reference="AUTH-2026-042",
            target_url="https://test.com/api/v1/health",
            test_type=TestType.ENDPOINT_PROBE,
            dry_run=True,
            max_requests=5,
            rate_limit=5,
            description="Health check endpoint probe",
            allowed_domains=["test.com"],
        )
        
        test = await engine.create_test(config, created_by="pentester01")
        assert test.status == TestStatus.DRAFT
        
        # Authorize
        success = await engine.authorize_test(test.test_id, authorized_by="security_manager")
        assert success is True
        assert test.status == TestStatus.AUTHORIZED
        
        # Execute
        success = await engine.execute_test(test.test_id, started_by="pentester01")
        assert success is True
        assert test.status == TestStatus.RUNNING
        
        # Wait for completion
        await asyncio.sleep(3)
        
        assert test.status == TestStatus.COMPLETED
        assert test.result in [TestResult.SUCCESS, TestResult.PARTIAL_SUCCESS]
        # Dry run doesn't send actual requests, so requests_sent may be 0
        assert test.end_time is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
