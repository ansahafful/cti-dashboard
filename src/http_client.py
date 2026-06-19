"""Resilient asynchronous HTTP plumbing shared by every API client.

This module provides a single :class:`AsyncFetcher` that wraps ``httpx`` with:

* **Per-host concurrency limiting** via an :class:`asyncio.Semaphore`.
* **Token-bucket request spacing** so we never breach published rate limits.
* **Exponential backoff with jitter**, honouring ``Retry-After`` headers and
  the retryable status codes declared in :data:`config.RETRY_POLICY`.
* **Structured logging** of every attempt for observability.

Keeping this concern in one place means the NVD, CISA, OTX, AbuseIPDB and
GeoIP clients all inherit identical, battle-tested resilience behaviour.
"""

from __future__ import annotations

import asyncio
import logging
import random
from types import TracebackType
from typing import Any

import httpx

from config import REQUEST_TIMEOUT, RETRY_POLICY, EndpointConfig, RetryPolicy

logger = logging.getLogger("cti.http")


class RateLimiter:
    """A minimal async token-bucket enforcing a minimum inter-request gap.

    Parameters
    ----------
    min_interval:
        Minimum number of seconds that must elapse between two successive
        acquisitions. A value of ``0`` disables spacing.
    """

    def __init__(self, min_interval: float) -> None:
        self._min_interval = max(0.0, min_interval)
        self._lock = asyncio.Lock()
        self._last_release = 0.0

    async def acquire(self) -> None:
        """Block until the configured spacing has elapsed."""
        if self._min_interval <= 0:
            return
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            wait = self._min_interval - (now - self._last_release)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_release = asyncio.get_event_loop().time()


class AsyncFetcher:
    """Rate-limit-aware async HTTP client for a single upstream endpoint.

    Use as an async context manager so the underlying connection pool is
    closed deterministically::

        async with AsyncFetcher(config.NVD, headers=...) as fetcher:
            payload = await fetcher.get_json(url, params=...)
    """

    def __init__(
        self,
        endpoint: EndpointConfig,
        *,
        headers: dict[str, str] | None = None,
        retry_policy: RetryPolicy = RETRY_POLICY,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self.endpoint = endpoint
        self.retry_policy = retry_policy
        self._semaphore = asyncio.Semaphore(endpoint.max_concurrency)
        self._limiter = RateLimiter(endpoint.min_interval)
        self._client = httpx.AsyncClient(
            headers=headers or {},
            timeout=timeout,
            follow_redirects=True,
        )

    async def __aenter__(self) -> "AsyncFetcher":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Backoff helpers
    # ------------------------------------------------------------------ #
    def _backoff_delay(self, attempt: int) -> float:
        """Compute an exponential backoff delay (seconds) with jitter."""
        policy = self.retry_policy
        raw = policy.base_delay * (2 ** (attempt - 1))
        capped = min(raw, policy.max_delay)
        jitter = capped * policy.jitter * random.random()
        return capped + jitter

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        """Parse a ``Retry-After`` header into seconds if present."""
        value = response.headers.get("Retry-After")
        if value is None:
            return None
        try:
            return float(value)
        except ValueError:
            return None

    # ------------------------------------------------------------------ #
    # Core request method
    # ------------------------------------------------------------------ #
    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """GET ``url`` and return parsed JSON, with retries and backoff.

        Returns ``None`` only when every attempt has been exhausted, allowing
        callers to degrade gracefully rather than crash the whole pipeline.
        """
        return await self.request_json("GET", url, params=params)

    async def post_json(
        self,
        url: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """POST ``json`` to ``url`` and return parsed JSON (with retries)."""
        return await self.request_json("POST", url, json=json, params=params)

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Perform a resilient JSON request, returning ``None`` on hard failure."""
        policy = self.retry_policy
        last_error: str = "unknown error"

        for attempt in range(1, policy.max_attempts + 1):
            async with self._semaphore:
                await self._limiter.acquire()
                try:
                    response = await self._client.request(
                        method, url, params=params, json=json
                    )
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    last_error = f"transport error: {exc!r}"
                    logger.warning(
                        "[%s] attempt %d/%d failed (%s)",
                        self.endpoint.name,
                        attempt,
                        policy.max_attempts,
                        last_error,
                    )
                else:
                    if response.status_code in policy.retry_statuses:
                        retry_after = self._retry_after(response)
                        last_error = f"HTTP {response.status_code}"
                        logger.warning(
                            "[%s] attempt %d/%d throttled/server error (%s)",
                            self.endpoint.name,
                            attempt,
                            policy.max_attempts,
                            last_error,
                        )
                        if retry_after is not None:
                            await asyncio.sleep(retry_after)
                            continue
                    elif response.is_success:
                        try:
                            return response.json()
                        except ValueError as exc:
                            logger.error(
                                "[%s] invalid JSON: %r", self.endpoint.name, exc
                            )
                            return None
                    else:
                        # Non-retryable client error (e.g. 401/403/404).
                        logger.error(
                            "[%s] non-retryable HTTP %d for %s",
                            self.endpoint.name,
                            response.status_code,
                            url,
                        )
                        return None

            # Exhausted this attempt; back off unless it was the last one.
            if attempt < policy.max_attempts:
                delay = self._backoff_delay(attempt)
                logger.info(
                    "[%s] backing off %.2fs before retry", self.endpoint.name, delay
                )
                await asyncio.sleep(delay)

        logger.error(
            "[%s] giving up on %s after %d attempts (%s)",
            self.endpoint.name,
            url,
            policy.max_attempts,
            last_error,
        )
        return None
