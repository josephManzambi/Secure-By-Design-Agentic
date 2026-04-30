"""
Rate Limiter
=============
Token-bucket rate limiter for MCP server tool invocations.

Framework alignment:
    OWASP LLM10 (Unbounded Consumption):
        "Repeated requests — an attacker floods the LLM API with repeated
        requests, disrupting service for legitimate users." Rate limiting
        at the tool level prevents a compromised agent from overwhelming
        the server with rapid tool calls.

    NIST AI 600-1 §5.10:
        Resource consumption controls for generative AI systems.

    CSA AICM AIS-12:
        "Resource consumption controls for AI system interfaces."

DESIGN DECISION:
    We use a simple token-bucket algorithm. In production, you'd
    use a distributed rate limiter (Redis-based, etc.). For this
    educational implementation, an in-memory token bucket demonstrates
    the principle clearly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class TokenBucket:
    """
    Token-bucket rate limiter.

    tokens_per_second: Rate at which tokens are added
    max_tokens: Maximum bucket capacity (burst size)
    """

    tokens_per_second: float
    max_tokens: float
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: Lock = field(init=False, default_factory=Lock)

    def __post_init__(self) -> None:
        self._tokens = self.max_tokens
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self.max_tokens,
            self._tokens + elapsed * self.tokens_per_second,
        )
        self._last_refill = now

    def try_consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens. Returns True if allowed, False if rate-limited.

        Thread-safe.
        """
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    @property
    def available_tokens(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens


class RateLimiter:
    """
    Per-tool rate limiter for the MCP server.

    Each tool gets its own token bucket, allowing different rate limits
    for different risk levels:
    - Safe tools (health_check, system_info): higher limits
    - Sensitive tools (read_log, search_logs): lower limits
    """

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._global_bucket = TokenBucket(
            tokens_per_second=5.0,  # 5 calls/sec globally
            max_tokens=20.0,        # burst of 20
        )

    def configure_tool(
        self,
        tool_name: str,
        tokens_per_second: float = 1.0,
        max_tokens: float = 5.0,
    ) -> None:
        """Configure rate limits for a specific tool."""
        self._buckets[tool_name] = TokenBucket(
            tokens_per_second=tokens_per_second,
            max_tokens=max_tokens,
        )

    def check(self, tool_name: str) -> bool:
        """
        Check if a tool call is allowed under rate limits.

        Returns True if allowed, False if rate-limited.
        Checks both the per-tool limit AND the global limit.
        """
        # Global rate limit
        if not self._global_bucket.try_consume():
            return False

        # Per-tool rate limit (if configured)
        bucket = self._buckets.get(tool_name)
        if bucket and not bucket.try_consume():
            return False

        return True


# Default rate limiter instance with sensible defaults
def create_default_limiter() -> RateLimiter:
    """Create a rate limiter with default per-tool limits."""
    limiter = RateLimiter()

    # Safe tools: generous limits
    limiter.configure_tool("health_check", tokens_per_second=5.0, max_tokens=20.0)
    limiter.configure_tool("system_info", tokens_per_second=2.0, max_tokens=10.0)

    # Sensitive tools: restrictive limits
    limiter.configure_tool("read_log", tokens_per_second=0.5, max_tokens=3.0)
    limiter.configure_tool("search_logs", tokens_per_second=0.5, max_tokens=3.0)

    return limiter
