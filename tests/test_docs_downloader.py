"""
Tests for docs_downloader.py:

  - html_to_text          (HTML -> stripped plain text)
  - url_to_path           (URL -> safe nested Linux filename)
  - detect_attack_surface (find real attack surface on a page)
  - decide_critical       (yes/no + reason for critical mode)

Network code is exercised manually.
"""
from pathlib import Path

from docs_downloader import (
    html_to_text,
    url_to_path,
    detect_attack_surface,
    decide_critical,
    INJECTABLE_PARAM_NAMES,
    INJECTABLE_INPUT_TYPES,
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
        assert "     " not in out

    def test_preserves_paragraph_breaks(self):
        html = "<p>first</p>\n\n\n\n<p>second</p>"
        out = html_to_text(html)
        assert "\n\n" in out


class TestUrlToPath:
    def _root(self, tmp_path):
        return tmp_path / "vault"

    def test_simple_path(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/foo", root)
        assert "example.com" in out.parts
        assert out.suffix == ".txt"
        assert out.stem.endswith("foo")

    def test_trailing_slash_becomes_index(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/", root)
        assert out.name.startswith("index")

    def test_root_path_is_index(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/", root)
        assert out.name == "index.txt"

    def test_strips_unsafe_chars(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/foo?id=1", root)
        assert "?" not in out.name
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
        assert "b" not in str(out).split("example.com/")[-1].split("/")[:-1]

    def test_long_segment_truncated(self, tmp_path):
        root = self._root(tmp_path)
        long_seg = "x" * 300
        out = url_to_path(f"https://example.com/{long_seg}", root)
        for part in out.parts:
            if part.startswith("x"):
                assert len(part) <= 205

    def test_host_becomes_top_directory(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs", root)
        rel = out.relative_to(root)
        assert rel.parts[0] == "example.com"

    def test_query_encoded_into_filename(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/a?key=value", root)
        assert "_q_" in out.name
        assert "key" in out.name
        assert "value" in out.name

    def test_writable_path_after_mkdir(self, tmp_path):
        root = self._root(tmp_path)
        out = url_to_path("https://example.com/docs/foo?x=1&y=2<>", root)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("hello")
        assert out.read_text() == "hello"


# -------------------------------------------------------------------
# detect_attack_surface - the new critical-mode detector
# -------------------------------------------------------------------
class TestDetectAttackSurfaceURL:
    def test_url_with_injectable_param_id(self):
        s = detect_attack_surface("https://target.com/?id=1", "")
        assert any("injectable" in x.lower() for x in s)
        assert any("id" in x for x in s)

    def test_url_with_injectable_param_file(self):
        s = detect_attack_surface("https://target.com/page?file=/etc/passwd", "")
        assert any("injectable" in x.lower() for x in s)

    def test_url_with_redirect_param(self):
        s = detect_attack_surface("https://target.com/login?redirect=/home", "")
        assert any("injectable" in x.lower() for x in s)

    def test_url_with_generic_param_still_kept(self):
        # An unfamiliar param name is still surface - just not flagged "injectable"
        s = detect_attack_surface("https://target.com/?weird_thing=x", "")
        assert any("query params" in x.lower() for x in s)

    def test_url_without_query_no_url_signal(self):
        s = detect_attack_surface("https://target.com/path", "")
        # No URL-based signal expected
        assert not any("URL" in x for x in s)

    def test_multiple_injectable_params_listed(self):
        s = detect_attack_surface(
            "https://t.com/?id=1&user=alice&file=/etc", "")
        # All three should be flagged as injectable
        sig = next(x for x in s if "injectable" in x.lower())
        for name in ("id", "user", "file"):
            assert name in sig


class TestDetectAttackSurfaceForms:
    def test_file_upload_detected(self):
        html = '<form><input type="file" name="upload"></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert any("file upload" in x.lower() for x in s)

    def test_password_login_detected(self):
        html = '<form><input type="text" name="u"><input type="password" name="p"></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert any("password" in x.lower() or "login" in x.lower() for x in s)

    def test_text_input_form_detected(self):
        html = '<form><input type="text" name="comment"></form>'
        s = detect_attack_surface("https://t.com/", html)
        # 'comment' is in INJECTABLE_PARAM_NAMES
        assert any("injectable" in x.lower() for x in s)

    def test_textarea_form_detected(self):
        html = '<form><textarea name="body"></textarea></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert any("injectable" in x.lower() or "form" in x.lower() for x in s)

    def test_input_without_type_defaults_to_text(self):
        # <input> with no type attr defaults to "text" per HTML spec
        html = '<form><input name="email"></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert any("injectable" in x.lower() for x in s)  # 'email' is injectable

    def test_form_with_only_submit_button_ignored(self):
        # No text-like inputs - not surface
        html = '<form><input type="submit" value="Go"></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert s == []

    def test_form_with_only_checkbox_ignored(self):
        html = '<form><input type="checkbox" name="agree"></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert s == []

    def test_form_with_only_radio_ignored(self):
        html = ('<form><input type="radio" name="x" value="a">'
                '<input type="radio" name="x" value="b"></form>')
        s = detect_attack_surface("https://t.com/", html)
        assert s == []

    def test_injectable_input_name_called_out(self):
        html = '<form><input type="text" name="id"></form>'
        s = detect_attack_surface("https://t.com/", html)
        sig = next(x for x in s if "injectable" in x.lower())
        assert "id" in sig

    def test_non_injectable_named_form_still_kept(self):
        # 'weird_thing' isn't in our list - still a form with text inputs
        html = '<form><input type="text" name="weird_thing"></form>'
        s = detect_attack_surface("https://t.com/", html)
        assert any("form" in x.lower() for x in s)

    def test_multiple_forms_counted(self):
        html = ('<form><input type="text" name="aaa"></form>'
                '<form><input type="text" name="bbb"></form>')
        s = detect_attack_surface("https://t.com/", html)
        # If neither name is in INJECTABLE_PARAM_NAMES we expect "2 form(s)"
        sig = next((x for x in s if "form" in x.lower() and "with text" in x.lower()), None)
        if sig:
            assert "2" in sig

    def test_case_insensitive_html_tags(self):
        html = '<FORM><INPUT TYPE="text" NAME="email"></FORM>'
        s = detect_attack_surface("https://t.com/", html)
        assert len(s) > 0

    def test_single_quoted_attrs(self):
        html = "<form><input type='text' name='id'></form>"
        s = detect_attack_surface("https://t.com/", html)
        assert any("injectable" in x.lower() for x in s)

    def test_unquoted_attrs(self):
        html = "<form><input type=text name=id></form>"
        s = detect_attack_surface("https://t.com/", html)
        # The name regex requires either quotes or non-space; 'id' has no space
        assert any("injectable" in x.lower() for x in s)


class TestDetectAttackSurfaceAPI:
    def test_json_object_response(self):
        s = detect_attack_surface("https://t.com/api/x",
                                    '{"id": 1, "name": "alice"}')
        assert any("json" in x.lower() for x in s)

    def test_json_array_response(self):
        s = detect_attack_surface("https://t.com/api/x", '[{"id": 1}]')
        assert any("json" in x.lower() for x in s)

    def test_xml_declaration_response(self):
        s = detect_attack_surface(
            "https://t.com/api/x",
            '<?xml version="1.0"?><root></root>')
        assert any("xml" in x.lower() for x in s)

    def test_json_with_leading_whitespace(self):
        s = detect_attack_surface("https://t.com/api/x", '   \n{"id": 1}')
        assert any("json" in x.lower() for x in s)

    def test_html_not_detected_as_api(self):
        s = detect_attack_surface("https://t.com/", '<html><body></body></html>')
        # HTML doesn't start with { [ or <?xml
        assert not any("json" in x.lower() for x in s)
        assert not any("xml" in x.lower() for x in s)


class TestDetectAttackSurfaceNegative:
    def test_static_marketing_page_no_surface(self):
        html = """
        <html><body>
          <h1>Welcome to Acme</h1>
          <p>We are the best company.</p>
          <p>Founded 2010.</p>
        </body></html>
        """
        assert detect_attack_surface("https://acme.com/about", html) == []

    def test_blog_post_no_surface(self):
        html = """
        <article>
          <h1>Our 2025 Year in Review</h1>
          <p>Lots of words here.</p>
        </article>
        """
        assert detect_attack_surface("https://acme.com/blog/2025", html) == []

    def test_static_page_with_links_only(self):
        html = '<a href="/x">x</a><a href="/y">y</a>'
        # Links are useful for crawling but not surface to attack
        assert detect_attack_surface("https://acme.com/", html) == []


class TestDetectAttackSurfaceCombined:
    def test_all_signals_collected(self):
        html = """
        <form>
          <input type="text" name="id">
          <input type="password" name="p">
          <input type="file" name="avatar">
        </form>
        """
        s = detect_attack_surface("https://t.com/login?next=/home", html)
        # URL inject + password + file upload + injectable form name
        assert any("URL" in x for x in s)
        assert any("file upload" in x.lower() for x in s)
        assert any("password" in x.lower() or "login" in x.lower() for x in s)


# -------------------------------------------------------------------
# decide_critical - thin (keep, reason) wrapper around detector
# -------------------------------------------------------------------
class TestDecideCritical:
    def test_surface_page_kept(self):
        keep, reason = decide_critical(
            "https://t.com/?id=1",
            '<form><input type="text" name="q"></form>',
        )
        assert keep is True
        assert reason  # Non-empty signal list joined

    def test_no_surface_skipped(self):
        keep, reason = decide_critical(
            "https://t.com/about",
            "<html><body><h1>About</h1></body></html>",
        )
        assert keep is False
        assert "no attack surface" in reason.lower()

    def test_returns_tuple_shape(self):
        result = decide_critical("https://t.com/", "")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_login_page_kept(self):
        keep, _ = decide_critical(
            "https://t.com/login",
            '<form action="/login" method="post">'
            '<input type="text" name="user">'
            '<input type="password" name="pass"></form>',
        )
        assert keep is True

    def test_upload_page_kept(self):
        keep, _ = decide_critical(
            "https://t.com/profile",
            '<form><input type="file" name="avatar"></form>',
        )
        assert keep is True

    def test_api_endpoint_kept(self):
        keep, _ = decide_critical(
            "https://t.com/api/users", '[{"id":1,"name":"alice"}]',
        )
        assert keep is True


# -------------------------------------------------------------------
# Constants - guard against accidental edits
# -------------------------------------------------------------------
class TestInjectableConstants:
    def test_param_names_includes_obvious_ones(self):
        for name in ("id", "q", "search", "file", "url", "redirect",
                     "token", "cmd", "xml", "json"):
            assert name in INJECTABLE_PARAM_NAMES

    def test_param_names_are_lowercase(self):
        for n in INJECTABLE_PARAM_NAMES:
            assert n == n.lower(), f"non-lowercase: {n!r}"

    def test_input_types_includes_text_password_etc(self):
        for t in ("text", "password", "email", "url", "search",
                   "number", "tel", "hidden"):
            assert t in INJECTABLE_INPUT_TYPES

    def test_input_types_excludes_buttons_radio_etc(self):
        for t in ("submit", "button", "reset", "checkbox", "radio",
                   "image", "color", "range"):
            assert t not in INJECTABLE_INPUT_TYPES
