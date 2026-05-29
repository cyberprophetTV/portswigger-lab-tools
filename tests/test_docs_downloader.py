"""
Tests for docs_downloader.py - HTML-to-text + URL-to-filename
sanitization. Network code is exercised manually.
"""
from pathlib import Path

from docs_downloader import html_to_text, url_to_path


class TestHtmlToText:
    def test_strips_script_blocks(self):
        html = "<p>keep</p><script>var bad = 'x'</script><p>also</p>"
        out = html_to_text(html)
        assert "keep" in out
        assert "also" in out
        assert "var bad" not in out

    def test_strips_style_blocks(self):
        html = "<style>body { color: red; }</style><h1>title</h1>"
        assert "color:" not in html_to_text(html)
        assert "title" in html_to_text(html)

    def test_strips_navigation_chrome(self):
        html = ("<nav>Home | Logout</nav>"
                "<main>Real content here.</main>"
                "<footer>Copyright 2026</footer>")
        out = html_to_text(html)
        assert "Real content here." in out
        # nav + footer text gone
        assert "Logout" not in out
        assert "Copyright 2026" not in out

    def test_strips_html_comments(self):
        html = "<!-- secret dev note --><p>shown</p>"
        out = html_to_text(html)
        assert "secret" not in out
        assert "shown" in out

    def test_decodes_html_entities(self):
        html = "<p>5 &lt; 10 &amp; not 11</p>"
        out = html_to_text(html)
        assert "5 < 10 & not 11" in out

    def test_collapses_whitespace(self):
        html = "<p>spread     out</p>"
        out = html_to_text(html)
        assert "spread out" in out
        # No giant whitespace run
        assert "     " not in out

    def test_preserves_paragraph_breaks(self):
        html = "<p>first</p>\n\n\n\n<p>second</p>"
        out = html_to_text(html)
        # At least one blank line between (paragraph break preserved)
        assert "\n\n" in out


class TestUrlToPath:
    def _root(self, tmp_path):
        return tmp_path / "vault"

    def test_simple_path(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/foo", root)
        # Mirrors the URL path under host dir
        assert "example.com" in out.parts
        assert out.suffix == ".txt"
        assert out.stem.endswith("foo")

    def test_trailing_slash_becomes_index(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/", root)
        # Trailing slash -> index.txt at that directory
        assert out.name.startswith("index")

    def test_root_path_is_index(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/", root)
        assert out.name == "index.txt"

    def test_strips_unsafe_chars(self, tmp_path):
        root = self._root(tmp_path)
        # URL with `?` (would crash mkdir on Windows; safer everywhere)
        out = url_to_path("https://example.com/docs/foo?id=1", root)
        # Result must not contain `?` in the filename portion
        assert "?" not in out.name
        # And must contain the query encoded into the filename
        assert "id" in out.name
        assert "1" in out.name

    def test_special_chars_in_segment(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/a<b>:c", root)
        for char in '<>?*"|:':
            assert char not in out.name

    def test_parent_dot_dot_resolved(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/a/b/../c", root)
        # ../ should pop 'b', leaving a/c
        assert "b" not in str(out).split("example.com/")[-1].split("/")[:-1]

    def test_long_segment_truncated(self, tmp_path):
        root = self._root(tmp_path)
        long_seg = "x" * 300
        out = url_to_path(f"https://example.com/{long_seg}", root)
        # Each filesystem segment should be <= 200 chars
        for part in out.parts:
            # Allow tmp_path components to be long; check only OUR segments
            if part.startswith("x"):
                assert len(part) <= 205   # 200 + ext + buffer

    def test_host_becomes_top_directory(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs", root)
        # Path should include the hostname as a directory
        rel = out.relative_to(root)
        assert rel.parts[0] == "example.com"

    def test_query_encoded_into_filename(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/a?key=value", root)
        assert "_q_" in out.name
        assert "key" in out.name
        assert "value" in out.name

    def test_writable_path_after_mkdir(self, tmp_path):
        # End-to-end: pick a URL with assorted dangerous chars, mkdir
        # the parent, and write a file. Must not raise.
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/foo?x=1&y=2<>", root)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("hello")
        assert out.read_text() == "hello"
