"""
Tests for docs_downloader.py - HTML-to-text + URL-to-filename
sanitization + critical-content filtering. Network code is
exercised manually.
"""
from pathlib import Path

from docs_downloader import (
    html_to_text,
    url_to_path,
    is_critical_url,
    is_critical_text,
    is_critical,
    decide_critical,
    find_site_preset,
    site_preset_decision,
    count_code_blocks,
    SITE_PRESETS,
    CRITICAL_URL_PATTERNS,
    CRITICAL_KEYWORDS,
)


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


# -------------------------------------------------------------------
# Critical-content filter: the "only save vuln-relevant pages" mode
# -------------------------------------------------------------------
class TestIsCriticalUrl:
    def test_matches_obvious_vuln_path(self):
        url = "https://portswigger.net/web-security/sql-injection"
        assert is_critical_url(url, CRITICAL_URL_PATTERNS)

    def test_matches_xss_path(self):
        url = "https://portswigger.net/web-security/cross-site-scripting"
        assert is_critical_url(url, CRITICAL_URL_PATTERNS)

    def test_matches_partial_substring(self):
        # 'vulnerab' substring matches 'vulnerability', 'vulnerabilities', etc.
        url = "https://example.com/docs/vulnerabilities/top-10"
        assert is_critical_url(url, CRITICAL_URL_PATTERNS)

    def test_case_insensitive(self):
        url = "https://example.com/Web-Security/SQL-Injection"
        assert is_critical_url(url, CRITICAL_URL_PATTERNS)

    def test_no_match_on_marketing_page(self):
        url = "https://portswigger.net/about/pricing"
        # 'about' / 'pricing' are not in the vuln keyword list
        assert not is_critical_url(url, CRITICAL_URL_PATTERNS)

    def test_no_match_on_blog_root(self):
        url = "https://example.com/blog/2025"
        assert not is_critical_url(url, CRITICAL_URL_PATTERNS)

    def test_custom_patterns_override(self):
        url = "https://example.com/labs/race-condition-1"
        # Default list doesn't include "/labs/" by name; user can pass their own
        assert is_critical_url(url, ["/labs/"])

    def test_empty_pattern_list_matches_nothing(self):
        url = "https://example.com/sql-injection"
        # With no patterns provided, nothing should match (we shouldn't crash)
        assert not is_critical_url(url, [])


class TestIsCriticalText:
    def test_matches_sql_injection_in_body(self):
        text = "This article explains how SQL injection works"
        assert is_critical_text(text, CRITICAL_KEYWORDS)

    def test_matches_xss_phrase(self):
        text = "Cross-site scripting is a client-side vulnerability"
        assert is_critical_text(text, CRITICAL_KEYWORDS)

    def test_case_insensitive(self):
        text = "JSON Web Token implementations often have flaws"
        assert is_critical_text(text, CRITICAL_KEYWORDS)

    def test_no_match_on_marketing_copy(self):
        text = "Our world-class team delivers tailored solutions for enterprise customers."
        assert not is_critical_text(text, CRITICAL_KEYWORDS)

    def test_custom_keywords_override(self):
        text = "GraphQL introspection enumeration"
        assert is_critical_text(text, ["graphql"])

    def test_empty_keywords_matches_nothing(self):
        text = "this is full of sql injection xxe rce"
        assert not is_critical_text(text, [])


class TestIsCritical:
    def test_url_match_short_circuits(self):
        # URL matches even if body is generic - still critical
        keep, reason = is_critical(
            "https://example.com/sql-injection/cheatsheet",
            "Some generic prose without vuln-specific words.",
            CRITICAL_URL_PATTERNS,
            CRITICAL_KEYWORDS,
        )
        assert keep is True
        assert "URL" in reason

    def test_text_match_when_url_is_generic(self):
        # URL doesn't look vuln-y but the body talks about SQL injection
        keep, reason = is_critical(
            "https://example.com/blog/post-12345",
            "This week we look at SQL injection in production.",
            CRITICAL_URL_PATTERNS,
            CRITICAL_KEYWORDS,
        )
        assert keep is True
        assert "keyword" in reason or "body" in reason

    def test_both_fail_is_not_critical(self):
        keep, reason = is_critical(
            "https://example.com/about/team",
            "Meet our founders and learn about our mission.",
            CRITICAL_URL_PATTERNS,
            CRITICAL_KEYWORDS,
        )
        assert keep is False
        assert reason  # Non-empty explanation

    def test_returns_tuple_shape(self):
        result = is_critical(
            "https://example.com/x", "y",
            CRITICAL_URL_PATTERNS, CRITICAL_KEYWORDS,
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)


class TestCriticalListsAreNonEmpty:
    """Guard against accidentally clearing the curated lists."""
    def test_url_patterns_populated(self):
        assert len(CRITICAL_URL_PATTERNS) > 20

    def test_keywords_populated(self):
        assert len(CRITICAL_KEYWORDS) > 20

    def test_url_patterns_are_lowercase(self):
        # Filter logic lowercases the URL path then does substring
        # `in` checks, so patterns themselves must be lowercase.
        for p in CRITICAL_URL_PATTERNS:
            assert p == p.lower(), f"non-lowercase pattern: {p!r}"

    def test_keywords_are_lowercase(self):
        for k in CRITICAL_KEYWORDS:
            assert k == k.lower(), f"non-lowercase keyword: {k!r}"


# -------------------------------------------------------------------
# Site presets - the real critical-mode logic (URL allowlist per host)
# -------------------------------------------------------------------
class TestFindSitePreset:
    def test_finds_portswigger(self):
        name, preset = find_site_preset(
            "https://portswigger.net/web-security/sql-injection",
            SITE_PRESETS,
        )
        assert name == "portswigger"
        assert preset is not None

    def test_finds_owasp(self):
        name, _ = find_site_preset(
            "https://owasp.org/www-community/attacks/SQL_Injection",
            SITE_PRESETS,
        )
        assert name == "owasp"

    def test_finds_owasp_cheatsheet_subdomain(self):
        # cheatsheetseries.owasp.org is its own host in the preset
        name, _ = find_site_preset(
            "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html",
            SITE_PRESETS,
        )
        assert name == "owasp"

    def test_finds_hacktricks_book(self):
        name, _ = find_site_preset(
            "https://book.hacktricks.xyz/pentesting-web/sql-injection",
            SITE_PRESETS,
        )
        assert name == "hacktricks"

    def test_finds_hacktricks_wiki_variant(self):
        name, _ = find_site_preset(
            "https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html",
            SITE_PRESETS,
        )
        assert name == "hacktricks"

    def test_subdomain_matches_parent(self):
        # academy.portswigger.net should match portswigger.net via endswith
        name, _ = find_site_preset(
            "https://academy.portswigger.net/web-security/jwt",
            SITE_PRESETS,
        )
        assert name == "portswigger"

    def test_unknown_host_returns_none(self):
        name, preset = find_site_preset(
            "https://random-blog.example.com/post-123", SITE_PRESETS,
        )
        assert name is None
        assert preset is None

    def test_substring_host_doesnt_falsely_match(self):
        # "evil-portswigger.net" should NOT match portswigger.net
        # (it's not a real subdomain, just a substring)
        name, _ = find_site_preset(
            "https://evil-portswigger.net/fake", SITE_PRESETS,
        )
        assert name is None


class TestSitePresetDecision:
    def test_portswigger_academy_kept(self):
        preset = SITE_PRESETS["portswigger"]
        decision, _ = site_preset_decision(
            "https://portswigger.net/web-security/sql-injection",
            preset,
        )
        assert decision == "keep"

    def test_portswigger_about_skipped(self):
        preset = SITE_PRESETS["portswigger"]
        decision, _ = site_preset_decision(
            "https://portswigger.net/about/team", preset,
        )
        assert decision == "skip"

    def test_portswigger_customers_skipped(self):
        preset = SITE_PRESETS["portswigger"]
        decision, _ = site_preset_decision(
            "https://portswigger.net/customers/acme-corp", preset,
        )
        assert decision == "skip"

    def test_portswigger_all_topics_skipped_even_under_web_security(self):
        # /web-security/all-topics matches BOTH the deny (/web-security/all-topics)
        # AND the allow (/web-security/). Deny must win.
        preset = SITE_PRESETS["portswigger"]
        decision, reason = site_preset_decision(
            "https://portswigger.net/web-security/all-topics", preset,
        )
        assert decision == "skip"
        assert "deny" in reason.lower()

    def test_portswigger_burp_docs_kept(self):
        preset = SITE_PRESETS["portswigger"]
        decision, _ = site_preset_decision(
            "https://portswigger.net/burp/documentation/desktop/tools/intruder",
            preset,
        )
        assert decision == "keep"

    def test_owasp_cheatsheet_kept(self):
        preset = SITE_PRESETS["owasp"]
        decision, _ = site_preset_decision(
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            preset,
        )
        assert decision == "keep"

    def test_owasp_membership_skipped(self):
        preset = SITE_PRESETS["owasp"]
        decision, _ = site_preset_decision(
            "https://owasp.org/membership/", preset,
        )
        assert decision == "skip"

    def test_path_not_on_allowlist_skipped(self):
        preset = SITE_PRESETS["portswigger"]
        decision, reason = site_preset_decision(
            "https://portswigger.net/some/random/path", preset,
        )
        assert decision == "skip"
        assert "allowlist" in reason.lower()

    def test_case_insensitive(self):
        preset = SITE_PRESETS["portswigger"]
        decision, _ = site_preset_decision(
            "https://portswigger.net/Web-Security/SQL-Injection", preset,
        )
        assert decision == "keep"


class TestPresetIntegrity:
    """Static checks every preset definition must satisfy."""
    def test_every_preset_has_required_keys(self):
        for name, preset in SITE_PRESETS.items():
            assert "hosts" in preset, f"{name} missing hosts"
            assert "allow" in preset, f"{name} missing allow"
            assert "deny" in preset, f"{name} missing deny"

    def test_every_preset_has_at_least_one_host(self):
        for name, preset in SITE_PRESETS.items():
            assert len(preset["hosts"]) >= 1, f"{name} has no hosts"

    def test_every_preset_has_allow_entries(self):
        for name, preset in SITE_PRESETS.items():
            assert len(preset["allow"]) >= 1, f"{name} has empty allowlist"


class TestCodeBlockDensity:
    def test_zero_for_plain_text(self):
        assert count_code_blocks("<p>Hello world</p>") == 0

    def test_counts_pre_tags(self):
        html = "<pre>a</pre><pre>b</pre><pre>c</pre>"
        assert count_code_blocks(html) == 3

    def test_counts_code_tags(self):
        html = "<code>x</code><code>y</code>"
        assert count_code_blocks(html) == 2

    def test_counts_mixed(self):
        html = "<pre><code>a</code></pre><pre>b</pre>"
        # 2 <pre> + 1 <code> = 3 opening tags
        assert count_code_blocks(html) == 3

    def test_case_insensitive(self):
        html = "<PRE>a</PRE><Code>b</Code>"
        assert count_code_blocks(html) == 2

    def test_ignores_pretend_attrs(self):
        # pretty pictures, not <pre>
        html = "<pretend>nope</pretend>"
        assert count_code_blocks(html) == 0


class TestDecideCritical:
    """Layered decision: preset > code density > URL > keyword."""

    def test_preset_keep_wins_over_no_code(self):
        # PortSwigger academy URL, no code in body - preset should keep it
        keep, reason = decide_critical(
            url="https://portswigger.net/web-security/sql-injection",
            html="<p>just prose</p>",
            text="just prose",
            preset=SITE_PRESETS["portswigger"],
            url_patterns=CRITICAL_URL_PATTERNS,
            keywords=CRITICAL_KEYWORDS,
        )
        assert keep is True
        assert "preset" in reason

    def test_preset_skip_wins_over_keywords(self):
        # PortSwigger /about/ - even if body mentions "SQL injection" the
        # preset deny still wins (we trust the curated rule)
        keep, reason = decide_critical(
            url="https://portswigger.net/about/team",
            html="<p>We invented SQL injection research blah</p>",
            text="We invented SQL injection research blah",
            preset=SITE_PRESETS["portswigger"],
            url_patterns=CRITICAL_URL_PATTERNS,
            keywords=CRITICAL_KEYWORDS,
        )
        assert keep is False
        assert "preset" in reason

    def test_code_density_when_no_preset(self):
        html = "<pre>a</pre><pre>b</pre><pre>c</pre><pre>d</pre>"
        keep, reason = decide_critical(
            url="https://random.example.com/post/42",
            html=html,
            text="some generic prose",
            preset=None,
            url_patterns=[],     # disable URL fallback
            keywords=[],         # disable keyword fallback
        )
        assert keep is True
        assert "code" in reason.lower()

    def test_url_pattern_fallback_when_no_preset(self):
        # No preset, no code density - URL pattern keeps it
        keep, reason = decide_critical(
            url="https://random.example.com/sql-injection/post",
            html="<p>x</p>",
            text="x",
            preset=None,
            url_patterns=["sql-injection"],
            keywords=[],
        )
        assert keep is True
        assert "URL" in reason

    def test_body_keyword_fallback_when_no_preset(self):
        keep, reason = decide_critical(
            url="https://random.example.com/post/42",
            html="<p>x</p>",
            text="this article explains SQL injection in detail",
            preset=None,
            url_patterns=[],
            keywords=["sql injection"],
        )
        assert keep is True
        assert "keyword" in reason.lower() or "body" in reason.lower()

    def test_nothing_matches_when_no_preset(self):
        keep, reason = decide_critical(
            url="https://random.example.com/about",
            html="<p>company team photo</p>",
            text="company team photo",
            preset=None,
            url_patterns=[],
            keywords=[],
        )
        assert keep is False
        assert reason
