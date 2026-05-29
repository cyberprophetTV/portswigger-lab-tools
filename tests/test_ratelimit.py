"""
Tests for _ratelimit.RateLimiter.

Pure-Python tests - no network. Time-sensitive tests use a small
epsilon and patience so they pass reliably on slow CI machines.
"""
import time

from _ratelimit import RateLimiter


class TestProactiveCap:
    def test_no_cap_does_not_sleep(self):
        rl = RateLimiter(max_rps=0)
        # Two rapid waits should both return instantly.
        start = time.monotonic()
        rl.wait_if_needed()
        rl.wait_if_needed()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    def test_cap_enforces_min_interval(self):
        # 10 req/s = 100 ms min gap. Two consecutive waits should
        # take ~100 ms total.
        rl = RateLimiter(max_rps=10)
        start = time.monotonic()
        rl.wait_if_needed()
        rl.wait_if_needed()
        elapsed = time.monotonic() - start
        # Loose lower bound (sleep is best-effort), generous upper.
        assert 0.08 <= elapsed <= 0.25


class TestReactiveBackoff:
    def test_no_blocks_no_backoff(self):
        rl = RateLimiter(max_rps=0, block_threshold=1)
        rl.report_response(200)
        rl.report_response(404)
        rl.report_response(500)
        stats = rl.stats()
        assert stats["total_blocks_seen"] == 0
        assert stats["total_backoffs_triggered"] == 0
        assert not stats["in_backoff_now"]

    def test_429_triggers_backoff(self):
        rl = RateLimiter(max_rps=0, block_threshold=1)
        rl.report_response(429)
        stats = rl.stats()
        assert stats["total_blocks_seen"] == 1
        assert stats["total_backoffs_triggered"] == 1
        assert stats["in_backoff_now"] is True

    def test_threshold_requires_consecutive(self):
        # threshold=2 means we tolerate ONE 429 without backing off.
        rl = RateLimiter(max_rps=0, block_threshold=2)
        rl.report_response(429)
        assert rl.stats()["total_backoffs_triggered"] == 0
        # Second consecutive 429 triggers
        rl.report_response(429)
        assert rl.stats()["total_backoffs_triggered"] == 1

    def test_success_resets_counter(self):
        # Two 429s, then a 200, then a 429: still only one trigger
        # (because the 200 reset the consecutive counter).
        rl = RateLimiter(max_rps=0, block_threshold=2)
        rl.report_response(429)
        rl.report_response(200)
        rl.report_response(429)
        # Only 1 consecutive 429 again - below threshold
        assert rl.stats()["total_backoffs_triggered"] == 0

    def test_none_status_does_not_count(self):
        # Connection errors (None) shouldn't be treated as rate limit
        # signals - that'd cause spurious backoffs on flaky networks.
        rl = RateLimiter(max_rps=0, block_threshold=1)
        rl.report_response(None)
        assert rl.stats()["total_blocks_seen"] == 0

    def test_custom_block_codes(self):
        # Some sites use 503 instead of 429
        rl = RateLimiter(max_rps=0, block_threshold=1, block_codes=(503,))
        rl.report_response(429)   # not in block_codes -> ignored
        rl.report_response(503)   # triggers
        assert rl.stats()["total_blocks_seen"] == 1
        assert rl.stats()["total_backoffs_triggered"] == 1

    def test_max_backoff_caps_sleep(self):
        # Even after many 429s, single-cycle backoff shouldn't blow up.
        rl = RateLimiter(max_rps=0, block_threshold=1, max_backoff=0.05)
        for _ in range(10):
            rl.report_response(429)
        # Now wait_if_needed should sleep AT MOST max_backoff seconds.
        start = time.monotonic()
        rl.wait_if_needed()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5   # comfortably above 0.05 but rules out 60s default
