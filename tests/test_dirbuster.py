"""
Tests for dirbuster.py - pure-logic pieces only (the network probe
loop and recursion driver aren't unit-tested; they'd need a fixture
server).
"""
from dirbuster import (
    DEFAULT_INTERESTING_STATUSES, DirBusterConfig,
    is_interesting, looks_like_directory,
)
from intruder import parse_range_spec


class TestDefaultStatuses:
    def test_includes_existence_signals(self):
        # 401/403 are critical - they mean "exists, just blocked".
        # Without them we'd miss every protected admin page.
        for code in (200, 301, 302, 401, 403):
            assert code in DEFAULT_INTERESTING_STATUSES

    def test_excludes_not_found(self):
        # 404 is the negative signal - including it would flag every
        # non-existent path and there'd be no filtering.
        assert 404 not in DEFAULT_INTERESTING_STATUSES


class TestIsInteresting:
    def _cfg(self, match_status=None):
        return DirBusterConfig(
            base_url="x", wordlist=[], extensions=[], workers=1,
            jitter=(0, 0), proxy=None, insecure=False, retries=0,
            cookies={}, verbose=False, match_status=match_status,
        )

    def test_default_set_matches(self):
        cfg = self._cfg()
        assert is_interesting(cfg, 200)
        assert is_interesting(cfg, 403)
        assert not is_interesting(cfg, 404)

    def test_match_status_overrides_default(self):
        # User says "I only care about 5xx" - 200 should no longer
        # be flagged even though it's in the default set.
        cfg = self._cfg(match_status=parse_range_spec("500-599"))
        assert is_interesting(cfg, 500)
        assert is_interesting(cfg, 503)
        assert not is_interesting(cfg, 200)

    def test_match_status_negation(self):
        cfg = self._cfg(match_status=parse_range_spec("!404"))
        assert is_interesting(cfg, 200)
        assert is_interesting(cfg, 500)
        assert not is_interesting(cfg, 404)


class TestLooksLikeDirectory:
    def test_301_to_trailing_slash(self):
        # The classic "/admin -> /admin/" redirect that signals
        # a real directory.
        assert looks_like_directory(301, 0, "/admin/", "/admin")

    def test_302_to_trailing_slash(self):
        assert looks_like_directory(302, 0, "/users/", "/users")

    def test_redirect_without_trailing_slash_does_not_qualify(self):
        # Some sites redirect /old to /new (rename), not a directory.
        assert not looks_like_directory(301, 0, "/new", "/old")

    def test_200_with_trailing_slash_qualifies(self):
        # Server served / directly (no redirect): still a directory.
        assert looks_like_directory(200, 0, "", "/admin/")

    def test_403_with_trailing_slash_qualifies(self):
        # Directory listing forbidden, but the dir is real.
        assert looks_like_directory(403, 0, "", "/private/")

    def test_404_does_not_qualify(self):
        # We don't recurse on 404 even with a trailing slash - that'd
        # be a generic miss, not a directory.
        assert not looks_like_directory(404, 0, "", "/x/")
