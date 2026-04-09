"""Tests for rate limiting and resource management."""
import asyncio
import pytest
import time

from core.rate_limiter import (
    RateLimiter,
    ConcurrencyLimiter,
    TimeoutManager,
    ResourceMonitor,
    RateLimitExceeded,
    ResourceLimitExceeded,
)


class TestRateLimiter:
    """Test rate limiter."""

    def test_within_limit(self):
        """Test requests within limit."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        for _ in range(5):
            assert limiter.check_limit("user1") is True

    def test_exceeds_limit(self):
        """Test requests exceeding limit."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        
        # First 3 should pass
        for _ in range(3):
            assert limiter.check_limit("user1") is True
        
        # 4th should fail
        assert limiter.check_limit("user1") is False

    def test_separate_users(self):
        """Test separate limits for different users."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        
        assert limiter.check_limit("user1") is True
        assert limiter.check_limit("user1") is True
        assert limiter.check_limit("user2") is True
        assert limiter.check_limit("user2") is True
        
        # Both users should be at limit
        assert limiter.check_limit("user1") is False
        assert limiter.check_limit("user2") is False

    def test_window_expiry(self):
        """Test that old requests expire."""
        limiter = RateLimiter(max_requests=2, window_seconds=1)
        
        # Use up limit
        assert limiter.check_limit("user1") is True
        assert limiter.check_limit("user1") is True
        assert limiter.check_limit("user1") is False
        
        # Wait for window to expire
        time.sleep(1.1)
        
        # Should be able to make requests again
        assert limiter.check_limit("user1") is True

    def test_get_remaining(self):
        """Test getting remaining requests."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        assert limiter.get_remaining("user1") == 5
        
        limiter.check_limit("user1")
        assert limiter.get_remaining("user1") == 4
        
        limiter.check_limit("user1")
        limiter.check_limit("user1")
        assert limiter.get_remaining("user1") == 2

    def test_reset(self):
        """Test resetting rate limit."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        
        limiter.check_limit("user1")
        limiter.check_limit("user1")
        assert limiter.check_limit("user1") is False
        
        limiter.reset("user1")
        assert limiter.check_limit("user1") is True


class TestConcurrencyLimiter:
    """Test concurrency limiter."""

    @pytest.mark.asyncio
    async def test_within_limit(self):
        """Test operations within concurrency limit."""
        limiter = ConcurrencyLimiter(max_concurrent=3)
        
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        
        assert limiter.get_active_count() == 3
        assert limiter.get_available_slots() == 0

    @pytest.mark.asyncio
    async def test_release(self):
        """Test releasing slots."""
        limiter = ConcurrencyLimiter(max_concurrent=2)
        
        await limiter.acquire()
        await limiter.acquire()
        assert limiter.get_active_count() == 2
        
        limiter.release()
        assert limiter.get_active_count() == 1
        assert limiter.get_available_slots() == 1

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Test timeout when waiting for slot."""
        limiter = ConcurrencyLimiter(max_concurrent=1)
        
        await limiter.acquire()
        
        with pytest.raises(ResourceLimitExceeded, match="Could not acquire slot"):
            await limiter.acquire(timeout=0.1)

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test using as context manager."""
        limiter = ConcurrencyLimiter(max_concurrent=2)
        
        async with limiter:
            assert limiter.get_active_count() == 1
        
        assert limiter.get_active_count() == 0

    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test multiple concurrent operations."""
        limiter = ConcurrencyLimiter(max_concurrent=2)
        results = []
        
        async def task(task_id):
            async with limiter:
                results.append(f"start-{task_id}")
                await asyncio.sleep(0.1)
                results.append(f"end-{task_id}")
        
        # Start 4 tasks, but only 2 should run concurrently
        await asyncio.gather(
            task(1), task(2), task(3), task(4)
        )
        
        assert len(results) == 8


class TestTimeoutManager:
    """Test timeout manager."""

    @pytest.mark.asyncio
    async def test_within_timeout(self):
        """Test operation completing within timeout."""
        async def quick_task():
            await asyncio.sleep(0.1)
            return "done"
        
        result = await TimeoutManager.run_with_timeout(
            quick_task(), timeout=1.0, operation_name="QuickTask"
        )
        assert result == "done"

    @pytest.mark.asyncio
    async def test_exceeds_timeout(self):
        """Test operation exceeding timeout."""
        async def slow_task():
            await asyncio.sleep(2.0)
            return "done"
        
        with pytest.raises(ResourceLimitExceeded, match="exceeded timeout"):
            await TimeoutManager.run_with_timeout(
                slow_task(), timeout=0.1, operation_name="SlowTask"
            )


class TestResourceMonitor:
    """Test resource monitor."""

    def test_start_end_scan(self):
        """Test starting and ending scan."""
        monitor = ResourceMonitor()
        
        monitor.start_scan(1)
        time.sleep(0.1)
        duration = monitor.end_scan(1)
        
        assert duration is not None
        assert duration >= 0.1

    def test_get_active_scans(self):
        """Test getting active scans."""
        monitor = ResourceMonitor()
        
        monitor.start_scan(1)
        monitor.start_scan(2)
        
        active = monitor.get_active_scans()
        assert len(active) == 2
        assert any(sid == 1 for sid, _ in active)
        assert any(sid == 2 for sid, _ in active)

    def test_check_scan_timeout(self):
        """Test checking scan timeout."""
        monitor = ResourceMonitor()
        
        monitor.start_scan(1)
        
        # Should not timeout immediately
        assert monitor.check_scan_timeout(1, max_duration=10.0) is False
        
        # Wait and check again
        time.sleep(0.2)
        assert monitor.check_scan_timeout(1, max_duration=0.1) is True

    def test_end_nonexistent_scan(self):
        """Test ending nonexistent scan."""
        monitor = ResourceMonitor()
        
        duration = monitor.end_scan(999)
        assert duration is None
