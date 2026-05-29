"""
Tests for response_diff.py - canonicalization + each diff mode.
"""
import pytest

from response_diff import (
    CanonConfig, DEFAULT_PATTERNS,
    canonicalize, render_unified_diff, render_summary, render_char_diff,
)


def _default_cfg():
    return CanonConfig(patterns=DEFAULT_PATTERNS)


class TestCanonicalize:
    def test_strips_csrf_token(self):
        html = '<input name="csrf" value="ABC123" />'
        out = canonicalize(html, _default_cfg())
        assert "ABC123" not in out
        assert "[STRIPPED]" in out

    def test_strips_csrf_value_first(self):
        html = '<input value="XYZ789" name="csrf" />'
        out = canonicalize(html, _default_cfg())
        assert "XYZ789" not in out

    def test_strips_uuid(self):
        text = "request id: 01234567-89ab-cdef-0123-456789abcdef"
        out = canonicalize(text, _default_cfg())
        assert "01234567" not in out

    def test_strips_iso_timestamp(self):
        text = "generated at 2026-05-29T14:23:01Z"
        out = canonicalize(text, _default_cfg())
        assert "2026-05-29" not in out

    def test_strips_cache_buster(self):
        text = '<script src="app.js?v=abc123def"></script>'
        out = canonicalize(text, _default_cfg())
        # Specifically the `?v=abc123def` part should be substituted.
        assert "?v=abc123def" not in out
        assert "app.js" in out   # path itself preserved

    def test_strips_jwt(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature"
        out = canonicalize(text, _default_cfg())
        assert "eyJhbGci" not in out

    def test_user_pattern_added(self):
        cfg = CanonConfig(patterns=[
            *DEFAULT_PATTERNS,
            ("custom request id", r'requestId":"[a-f0-9-]+"'),
        ])
        text = '{"requestId":"abc-123-def","user":"alice"}'
        out = canonicalize(text, cfg)
        assert "abc-123-def" not in out
        assert "alice" in out   # other content preserved

    def test_collapse_whitespace(self):
        cfg = CanonConfig(patterns=[], collapse_whitespace=True)
        text = "hello   world\n\n\nstuff"
        out = canonicalize(text, cfg)
        assert "   " not in out

    def test_no_strips_returns_input_unchanged(self):
        cfg = CanonConfig(patterns=[])
        text = "hello world"
        assert canonicalize(text, cfg) == text


class TestUnifiedDiff:
    def test_identical_returns_no_change(self):
        changed, out = render_unified_diff("hello", "hello")
        assert not changed
        assert out == ""

    def test_different_returns_diff(self):
        changed, out = render_unified_diff("line1\nline2\n", "line1\nlineX\n")
        assert changed
        assert "line2" in out
        assert "lineX" in out

    def test_after_canonicalization_csrf_change_is_invisible(self):
        # Two responses identical except for the CSRF token - after
        # canonicalization they should diff to nothing.
        a = '<form><input name="csrf" value="AAAA"></form>'
        b = '<form><input name="csrf" value="BBBB"></form>'
        ca = canonicalize(a, _default_cfg())
        cb = canonicalize(b, _default_cfg())
        changed, _ = render_unified_diff(ca, cb)
        assert not changed

    def test_real_signal_survives_canonicalization(self):
        # BSCP "subtly different" case: bodies differ by one literal
        # character (the period) - canonicalization must NOT eat it.
        a = '<p class=is-warning>Invalid username</p>'
        b = '<p class=is-warning>Invalid username.</p>'
        ca = canonicalize(a, _default_cfg())
        cb = canonicalize(b, _default_cfg())
        changed, out = render_unified_diff(ca, cb)
        assert changed
        # The differing char shows up in the diff.
        assert "Invalid username." in out


class TestSummary:
    def test_identical_returns_no_change(self):
        changed, out = render_summary("a\nb\nc", "a\nb\nc")
        assert not changed

    def test_reports_similarity_ratio(self):
        changed, out = render_summary("a\nb\nc\nd\ne", "a\nx\nc\ny\ne")
        assert changed
        assert "similarity ratio" in out


class TestCharDiff:
    def test_identical_returns_no_change(self):
        changed, out = render_char_diff("hello", "hello")
        assert not changed

    def test_single_char_difference_shown(self):
        changed, out = render_char_diff("Invalid username",
                                          "Invalid username.")
        assert changed
        # Both lines labeled A: and B:
        assert "A:" in out
        assert "B:" in out


class TestDefaultPatternsAreValidRegex:
    def test_every_default_pattern_compiles(self):
        # Catches accidentally-malformed regex in DEFAULT_PATTERNS
        # before users hit "wrong regex" errors at runtime.
        import re as _re
        for label, pattern in DEFAULT_PATTERNS:
            try:
                _re.compile(pattern, _re.IGNORECASE | _re.DOTALL)
            except _re.error as e:
                pytest.fail(f"DEFAULT_PATTERNS {label!r}: invalid regex - {e}")
