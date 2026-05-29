"""
Tests for proxy_spider.py - URL extraction + form-param extraction +
in-scope logic. Network code (crawl) is exercised manually.
"""
import argparse

from proxy_spider import (
    extract_urls, extract_form_params, in_scope,
)


class TestExtractUrls:
    def test_anchor_href(self):
        html = '<a href="/about">About</a>'
        assert extract_urls(html, "https://x.com/page") == {
            "https://x.com/about"
        }

    def test_form_action(self):
        html = '<form action="/submit" method="post"></form>'
        assert "https://x.com/submit" in extract_urls(html, "https://x.com/page")

    def test_script_src(self):
        html = '<script src="/js/app.js"></script>'
        assert "https://x.com/js/app.js" in extract_urls(html, "https://x.com/")

    def test_relative_url_resolved(self):
        html = '<a href="other.html">x</a>'
        assert extract_urls(html, "https://x.com/dir/page") == {
            "https://x.com/dir/other.html"
        }

    def test_parent_relative_url(self):
        html = '<a href="../up">x</a>'
        assert extract_urls(html, "https://x.com/a/b/page") == {
            "https://x.com/a/up"
        }

    def test_absolute_url_left_alone(self):
        html = '<a href="https://other.com/x">x</a>'
        assert extract_urls(html, "https://x.com/") == {
            "https://other.com/x"
        }

    def test_fragment_only_dropped(self):
        html = '<a href="#section">x</a>'
        assert extract_urls(html, "https://x.com/page") == set()

    def test_javascript_and_mailto_dropped(self):
        html = '<a href="javascript:alert(1)">x</a><a href="mailto:a@b">y</a>'
        assert extract_urls(html, "https://x.com/") == set()

    def test_fragment_stripped_from_url(self):
        html = '<a href="/page#section">x</a>'
        assert extract_urls(html, "https://x.com/") == {
            "https://x.com/page"
        }

    def test_multiple_url_types_in_one_doc(self):
        html = (
            '<a href="/about">A</a>'
            '<form action="/login"></form>'
            '<script src="/js/app.js"></script>'
            '<link href="/css/style.css">'
            '<img src="/img/logo.png">'
            '<iframe src="/embed"></iframe>'
        )
        urls = extract_urls(html, "https://x.com/")
        assert len(urls) == 6


class TestExtractFormParams:
    def test_input_name(self):
        html = '<input type="text" name="username">'
        assert extract_form_params(html) == {"username"}

    def test_textarea_name(self):
        html = '<textarea name="comment"></textarea>'
        assert extract_form_params(html) == {"comment"}

    def test_select_name(self):
        html = '<select name="country"><option>US</option></select>'
        assert extract_form_params(html) == {"country"}

    def test_button_name(self):
        html = '<button name="action" value="submit">Save</button>'
        assert extract_form_params(html) == {"action"}

    def test_multiple_inputs(self):
        html = ('<form><input name="user"><input name="pass">'
                '<textarea name="msg"></textarea></form>')
        assert extract_form_params(html) == {"user", "pass", "msg"}

    def test_unique_names_deduped(self):
        html = '<input name="x"><input name="x"><input name="y">'
        assert extract_form_params(html) == {"x", "y"}

    def test_no_form_inputs(self):
        assert extract_form_params("<p>just text</p>") == set()


class TestInScope:
    def _args(self, **kw):
        # Make an argparse.Namespace with default scope flags + overrides.
        defaults = {"any_host": False, "include_path": "", "exclude_path": ""}
        defaults.update(kw)
        return argparse.Namespace(**defaults)

    def test_same_host_default(self):
        assert in_scope("https://x.com/page", "x.com", self._args())
        assert not in_scope("https://other.com/x", "x.com", self._args())

    def test_any_host_allows_other_hosts(self):
        assert in_scope("https://other.com/x", "x.com",
                         self._args(any_host=True))

    def test_include_path_prefix(self):
        args = self._args(include_path="/api/")
        assert in_scope("https://x.com/api/v1/users", "x.com", args)
        assert not in_scope("https://x.com/admin", "x.com", args)

    def test_exclude_path_prefix(self):
        args = self._args(exclude_path="/logout")
        assert not in_scope("https://x.com/logout", "x.com", args)
        assert in_scope("https://x.com/profile", "x.com", args)

    def test_empty_netloc_rejected(self):
        # Malformed URL with no host - not in scope.
        assert not in_scope("just-a-string", "x.com", self._args())
