"""
Tests for _truncate.py - HTML noise stripping + truncation pipeline.
"""
from _truncate import (
    strip_html_noise, collapse_whitespace, truncate, compact_response,
)


class TestStripHtmlNoise:
    def test_removes_script_block(self):
        html = "<p>keep</p><script>alert(1)</script><p>also keep</p>"
        out = strip_html_noise(html)
        assert "<script>" not in out
        assert "alert" not in out
        assert "keep" in out
        assert "also keep" in out

    def test_removes_style_block(self):
        html = "<style>body { color: red; }</style><h1>title</h1>"
        out = strip_html_noise(html)
        assert "color:" not in out
        assert "title" in out

    def test_removes_svg(self):
        html = '<svg viewBox="0 0 1 1"><path d="..."/></svg><form></form>'
        out = strip_html_noise(html)
        assert "svg" not in out.lower()
        assert "<form>" in out

    def test_removes_img(self):
        html = '<img src="pic.png" alt="x"><h1>real content</h1>'
        out = strip_html_noise(html)
        assert "<img" not in out
        assert "real content" in out

    def test_removes_iframe(self):
        html = '<iframe src="x"></iframe><a href="/login">login</a>'
        out = strip_html_noise(html)
        assert "iframe" not in out.lower()
        assert "login" in out

    def test_removes_html_comments(self):
        html = "<!-- secret dev note --><h1>page</h1>"
        out = strip_html_noise(html)
        assert "secret" not in out
        assert "page" in out

    def test_removes_noscript(self):
        html = "<noscript>Please enable JS</noscript><form></form>"
        out = strip_html_noise(html)
        assert "Please enable JS" not in out

    def test_case_insensitive(self):
        html = "<SCRIPT>x</SCRIPT><Style>y</Style>"
        out = strip_html_noise(html)
        assert "SCRIPT" not in out
        assert "Style" not in out

    def test_preserves_forms_and_inputs(self):
        html = (
            '<script>var a=1</script>'
            '<form action="/login"><input name="user"><input name="pass"></form>'
            '<img src="x">'
        )
        out = strip_html_noise(html)
        assert "<form" in out
        assert 'name="user"' in out
        assert 'name="pass"' in out

    def test_preserves_links(self):
        html = '<a href="/admin">admin</a><script>x</script>'
        out = strip_html_noise(html)
        assert 'href="/admin"' in out

    def test_handles_nested_tags(self):
        # script inside a div - the script block should still go.
        html = '<div><script>secret</script><p>visible</p></div>'
        out = strip_html_noise(html)
        assert "secret" not in out
        assert "visible" in out

    def test_removes_link_stylesheet_tag(self):
        html = '<link rel="stylesheet" href="x.css"><h1>real</h1>'
        out = strip_html_noise(html)
        assert "<link" not in out
        assert "real" in out


class TestCollapseWhitespace:
    def test_collapses_spaces(self):
        assert collapse_whitespace("a    b") == "a b"

    def test_collapses_tabs(self):
        assert collapse_whitespace("a\t\t\tb") == "a b"

    def test_preserves_single_newlines(self):
        assert "\n" in collapse_whitespace("line1\nline2")

    def test_collapses_multiple_blank_lines(self):
        # Three or more newlines in a row -> one blank line (\n\n)
        out = collapse_whitespace("a\n\n\n\n\nb")
        assert out.count("\n") <= 3


class TestTruncate:
    def test_no_cap_returns_input(self):
        assert truncate("hello", 0) == "hello"
        assert truncate("hello", -1) == "hello"

    def test_short_input_returned_as_is(self):
        assert truncate("hi", 100) == "hi"

    def test_long_input_truncated_with_marker(self):
        out = truncate("x" * 1000, 50)
        # First 50 chars present
        assert out.startswith("x" * 50)
        # Truncation marker mentions the original size
        assert "truncated" in out
        assert "1000" in out


class TestCompactResponse:
    def test_pipeline_strips_then_truncates(self):
        # Build something big: noise + content + more noise
        big = ("<script>" + "a" * 10000 + "</script>"
               "<form><input name='u'></form>"
               "<style>" + "b" * 10000 + "</style>")
        out = compact_response(big, max_chars=200)
        # Noise must be gone first
        assert "a" * 100 not in out
        assert "b" * 100 not in out
        # Form preserved
        assert "<form>" in out or "form" in out.lower()
        # Result fits the cap (with truncation marker allowance)
        assert len(out) < 500

    def test_unlimited_when_max_chars_zero(self):
        big = "<form><input name='u'></form>"
        out = compact_response(big, max_chars=0)
        # Form survived, no truncation marker
        assert "form" in out
        assert "truncated" not in out
