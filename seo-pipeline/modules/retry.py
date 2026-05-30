"""Tiny exponential-backoff retry decorator.

We avoid pulling in tenacity for one helper. The decorator catches a tuple of
exceptions and retries with jitter up to `attempts` times, raising the final
exception on give-up.
"""

from __future__ import annotations

import functools
import random
import time
from typing import Callable, Tuple, Type, TypeVar

from modules.log_config import get_logger

log = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., object])


def retry(
    *,
    attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
) -> Callable[[F], F]:
    """Exponential backoff with full jitter. Re-raises on final failure."""

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            last_exc: BaseException | None = None
            for attempt in range(1, attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == attempts:
                        log.warning(
                            "%s failed after %d attempts: %s", fn.__name__, attempts, exc
                        )
                        raise
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    delay = random.uniform(0, delay)  # full jitter
                    log.info(
                        "%s attempt %d/%d failed (%s) — retrying in %.1fs",
                        fn.__name__, attempt, attempts, exc, delay,
                    )
                    time.sleep(delay)
            # unreachable, but keeps type checker happy
            raise last_exc  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator
