"""
_ratelimit.py
=============
Thread-safe rate limiter with BOTH a proactive token-bucket-style cap
(max requests per second) AND a reactive backoff when the server
starts returning 429 (Too Many Requests) or other "you're going too
fast" signals.

WHY BOTH?
---------
PROACTIVE (--max-rps): you set a hard ceiling on your request rate
that you stay below regardless of what the server does. Useful when
you KNOW the limit (e.g. BSCP exam labs cap at roughly 50 req/s;
running at 30 keeps you safely under).

REACTIVE (429 backoff): you don't always know the limit up front. If
the server starts saying 429, we detect it, sleep, and resume more
slowly. After N consecutive 429s we start exponential backoff
(1s, 2s, 4s, 8s, ... capped at 60s) until we get a non-429 again.

Without rate-limit awareness, an aggressive fuzz against a real
target gets you IP-banned mid-engagement (very bad on the BSCP exam
- there's a finite time budget and the cooldown isn't quick).
"""

import threading
import time


class RateLimiter:
    """
    Combined proactive cap + reactive backoff.

    Usage pattern (from a worker):
        rl.wait_if_needed()          # blocks until safe to send
        response = send_request()
        rl.report_response(response.status_code)
    """

    def __init__(self, max_rps: float = 0, block_threshold: int = 1,
                 block_codes: tuple[int, ...] = (429,),
                 max_backoff: float = 60.0):
        """
        max_rps:         requests per second cap. 0 = no proactive cap.
        block_threshold: how many consecutive `block_codes` responses
                         we tolerate before we start backing off. 1
                         means "any 429 triggers backoff". Some sites
                         issue spurious 429s, so >=2 reduces flapping.
        block_codes:     status codes we treat as "back off." Default
                         is just 429 (Too Many Requests); add 503 / 509
                         / your-custom-block-status if needed.
        max_backoff:     ceiling on the exponential backoff sleep, in
                         seconds. Don't sleep more than this between
                         retries even if we keep getting blocked.
        """
        self.max_rps = max_rps
        # Minimum time (seconds) between consecutive sends to honor max_rps.
        # Inf when max_rps=0 (no cap). 1/N pattern.
        self.min_interval = (1.0 / max_rps) if max_rps > 0 else 0.0
        self.block_threshold = block_threshold
        self.block_codes = set(block_codes)
        self.max_backoff = max_backoff

        # State - all access must hold self._lock.
        self._lock = threading.Lock()
        self._last_send_at = 0.0           # monotonic time of last permitted send
        self._consecutive_blocks = 0       # rolling count of N×block_codes in a row
        self._backoff_until = 0.0          # monotonic time we're allowed to send again
        # Stats (for debugging/reporting)
        self._total_blocks = 0
        self._total_backoffs = 0

    # -----------------------------------------------------------------
    # WORKER-SIDE API
    # -----------------------------------------------------------------
    def wait_if_needed(self) -> None:
        """
        Block until it's safe to send the next request, honoring both
        the proactive cap AND any active reactive backoff.

        Two-phase wait so we don't hold the lock during sleeps:
          1. Under the lock, compute how long to sleep.
          2. Release the lock and sleep.
          3. Re-acquire to record the send time.
        """
        # Compute sleep durations holding the lock briefly.
        with self._lock:
            now = time.monotonic()
            # Reactive: are we in a backoff window?
            backoff_wait = max(0.0, self._backoff_until - now)
            # Proactive: do we owe a min-interval gap?
            proactive_wait = 0.0
            if self.min_interval > 0:
                proactive_wait = max(0.0, self._last_send_at + self.min_interval - now)
            sleep_for = max(backoff_wait, proactive_wait)

        # Release the lock during the sleep so other workers can also
        # be computing/sleeping concurrently (they each wait based on
        # their own snapshot).
        if sleep_for > 0:
            time.sleep(sleep_for)

        # Record the send time so the next caller computes its
        # proactive wait correctly.
        with self._lock:
            self._last_send_at = time.monotonic()

    def report_response(self, status_code: int | None) -> None:
        """
        Call this once per HTTP response so the reactive logic can
        decide whether to start (or extend) a backoff window.

        Connection errors / None status DON'T count as blocks - they
        could be network noise unrelated to rate limiting.
        """
        if status_code is None:
            return
        with self._lock:
            if status_code in self.block_codes:
                self._consecutive_blocks += 1
                self._total_blocks += 1
                if self._consecutive_blocks >= self.block_threshold:
                    # Exponential backoff: 2^N seconds, capped.
                    # First trigger sleeps 1s, then 2s, 4s, 8s, ...
                    over = self._consecutive_blocks - self.block_threshold
                    delay = min(self.max_backoff, 2.0 ** over)
                    self._backoff_until = time.monotonic() + delay
                    self._total_backoffs += 1
            else:
                # Anything non-blocking resets the counter - the server
                # is responding again, get out of backoff.
                self._consecutive_blocks = 0

    # -----------------------------------------------------------------
    # OBSERVABILITY
    # -----------------------------------------------------------------
    def stats(self) -> dict:
        """Snapshot of internal counters (for end-of-run summary)."""
        with self._lock:
            return {
                "total_blocks_seen": self._total_blocks,
                "total_backoffs_triggered": self._total_backoffs,
                "in_backoff_now": time.monotonic() < self._backoff_until,
                "max_rps_cap": self.max_rps,
            }
