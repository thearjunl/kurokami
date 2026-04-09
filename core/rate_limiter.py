"""Rate limiting and resource management for production deployments."""
import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass


class ResourceLimitExceeded(Exception):
    """Raised when resource limit is exceeded."""
    pass


class RateLimiter:
    """Token bucket rate limiter with sliding window."""

    def __init__(self, max_requests: int, window_seconds: int = 3600):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in the window
            window_seconds: Time window in seconds (default: 1 hour)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = defaultdict(deque)
        self._lock = Lock()

    def check_limit(self, user_id: str = "default") -> bool:
        """
        Check if request is within rate limit.
        
        Args:
            user_id: Identifier for the user/client
            
        Returns:
            True if within limit, False otherwise
        """
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            # Remove old requests outside the window
            user_requests = self._requests[user_id]
            while user_requests and user_requests[0] < cutoff:
                user_requests.popleft()
            
            # Check if limit exceeded
            if len(user_requests) >= self.max_requests:
                return False
            
            # Add current request
            user_requests.append(now)
            return True

    def get_remaining(self, user_id: str = "default") -> int:
        """Get remaining requests in current window."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            user_requests = self._requests[user_id]
            # Count requests in current window
            valid_requests = sum(1 for req_time in user_requests if req_time >= cutoff)
            
            return max(0, self.max_requests - valid_requests)

    def get_reset_time(self, user_id: str = "default") -> Optional[datetime]:
        """Get time when rate limit will reset."""
        with self._lock:
            user_requests = self._requests[user_id]
            if not user_requests:
                return None
            
            oldest_request = user_requests[0]
            reset_time = oldest_request + self.window_seconds
            return datetime.fromtimestamp(reset_time)

    def reset(self, user_id: str = "default"):
        """Reset rate limit for a user."""
        with self._lock:
            if user_id in self._requests:
                del self._requests[user_id]


class ConcurrencyLimiter:
    """Limit concurrent operations using semaphore."""

    def __init__(self, max_concurrent: int):
        """
        Initialize concurrency limiter.
        
        Args:
            max_concurrent: Maximum concurrent operations allowed
        """
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_count = 0
        self._lock = Lock()

    async def acquire(self, timeout: Optional[float] = None):
        """
        Acquire a slot for concurrent operation.
        
        Args:
            timeout: Maximum time to wait for a slot (None = wait forever)
            
        Raises:
            ResourceLimitExceeded: If timeout expires
        """
        try:
            if timeout:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=timeout)
            else:
                await self._semaphore.acquire()
            
            with self._lock:
                self._active_count += 1
        except asyncio.TimeoutError:
            raise ResourceLimitExceeded(
                f"Could not acquire slot within {timeout}s. "
                f"Maximum concurrent operations: {self.max_concurrent}"
            )

    def release(self):
        """Release a slot."""
        self._semaphore.release()
        with self._lock:
            self._active_count = max(0, self._active_count - 1)

    def get_active_count(self) -> int:
        """Get number of active operations."""
        with self._lock:
            return self._active_count

    def get_available_slots(self) -> int:
        """Get number of available slots."""
        return self.max_concurrent - self.get_active_count()

    async def __aenter__(self):
        """Context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.release()


class TimeoutManager:
    """Manage operation timeouts."""

    @staticmethod
    async def run_with_timeout(coro, timeout: float, operation_name: str = "Operation"):
        """
        Run coroutine with timeout.
        
        Args:
            coro: Coroutine to run
            timeout: Timeout in seconds
            operation_name: Name for error messages
            
        Returns:
            Result of coroutine
            
        Raises:
            ResourceLimitExceeded: If timeout expires
        """
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            raise ResourceLimitExceeded(
                f"{operation_name} exceeded timeout of {timeout}s"
            )


class ResourceMonitor:
    """Monitor resource usage and enforce limits."""

    def __init__(self):
        """Initialize resource monitor."""
        self._scan_start_times = {}
        self._lock = Lock()

    def start_scan(self, session_id: int):
        """Record scan start time."""
        with self._lock:
            self._scan_start_times[session_id] = time.time()

    def end_scan(self, session_id: int) -> Optional[float]:
        """
        Record scan end and return duration.
        
        Returns:
            Duration in seconds, or None if not found
        """
        with self._lock:
            start_time = self._scan_start_times.pop(session_id, None)
            if start_time:
                return time.time() - start_time
            return None

    def get_active_scans(self) -> list[tuple[int, float]]:
        """
        Get list of active scans with their durations.
        
        Returns:
            List of (session_id, duration_seconds) tuples
        """
        with self._lock:
            now = time.time()
            return [
                (session_id, now - start_time)
                for session_id, start_time in self._scan_start_times.items()
            ]

    def check_scan_timeout(self, session_id: int, max_duration: float) -> bool:
        """
        Check if scan has exceeded maximum duration.
        
        Args:
            session_id: Session ID to check
            max_duration: Maximum allowed duration in seconds
            
        Returns:
            True if scan has timed out
        """
        with self._lock:
            start_time = self._scan_start_times.get(session_id)
            if not start_time:
                return False
            
            duration = time.time() - start_time
            return duration > max_duration


# Global instances
_rate_limiter: Optional[RateLimiter] = None
_concurrency_limiter: Optional[ConcurrencyLimiter] = None
_resource_monitor: Optional[ResourceMonitor] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        from .config import config
        _rate_limiter = RateLimiter(
            max_requests=config.max_scans_per_hour,
            window_seconds=3600
        )
    return _rate_limiter


def get_concurrency_limiter() -> ConcurrencyLimiter:
    """Get global concurrency limiter instance."""
    global _concurrency_limiter
    if _concurrency_limiter is None:
        from .config import config
        _concurrency_limiter = ConcurrencyLimiter(
            max_concurrent=config.max_concurrent_scans
        )
    return _concurrency_limiter


def get_resource_monitor() -> ResourceMonitor:
    """Get global resource monitor instance."""
    global _resource_monitor
    if _resource_monitor is None:
        _resource_monitor = ResourceMonitor()
    return _resource_monitor
