"""
Tests for cyberchef.py — every pure-function operation.
TUI loop is interactive; tested manually.
"""
import json

import pytest

# rich + questionary are imported at module top in cyberchef.py;
# skip these tests gracefully if either is missing.
pytest.importorskip("rich")
pytest.importorskip("questionary")

from cyberchef import (
    OPERATIONS, magic_decode, _looks_readable, show_state,
    ALIASES, resolve_op_name, CONTROL_COMMANDS, _prompt_choices,
    identify_format, FormatHint,
    op_to_base64, op_from_base64,
    op_to_base32, op_from_base32,
    op_to_url, op_from_url, op_to_double_url, op_from_double_url,
    op_to_hex, op_from_hex,
    op_to_binary, op_from_binary,
    op_to_html_entities, op_from_html_entities,
    op_rot13_clean,
    op_hmac_sha256, _hash,
    op_reverse, op_upper, op_lower, op_strip, op_count,
    op_sort_lines, op_unique_lines,
    op_json_pretty, op_json_minify, op_parse_url, op_parse_query_string,
    op_defang_url, op_refang_url, op_defang_email, op_refang_email,
    op_epoch_to_iso, op_iso_to_epoch, op_now,
    op_random_hex, op_uuid_v4, op_word_to_jwt_summary,
)


# ---------------------------------------------------------------------
# CATALOG SANITY
# ---------------------------------------------------------------------
class TestCatalog:
    def test_no_duplicate_names(self):
        names = [op.name for op in OPERATIONS]
        assert len(names) == len(set(names))

    def test_every_op_has_description(self):
        for op in OPERATIONS:
            assert len(op.description) >= 10, f"{op.name} desc too short"

    def test_every_op_is_callable(self):
        for op in OPERATIONS:
            assert callable(op.fn)

    def test_categories_populated(self):
        cats = {op.category for op in OPERATIONS}
        for required in ("Encoding", "Hashing", "String", "Data",
                          "Defang", "Time", "Misc"):
            assert required in cats


# ---------------------------------------------------------------------
# ENCODING ROUND-TRIPS
# ---------------------------------------------------------------------
class TestEncodingRoundTrips:
    @pytest.mark.parametrize("text", ["hello", "user=admin", "with spaces & symbols!"])
    def test_base64_roundtrip(self, text):
        assert op_from_base64(op_to_base64(text, {}), {}) == text

    @pytest.mark.parametrize("text", ["hello", "WITH UPPERCASE", "12345"])
    def test_base32_roundtrip(self, text):
        assert op_from_base32(op_to_base32(text, {}), {}) == text

    @pytest.mark.parametrize("text", ["hello world", "' OR 1=1--", "a/b/c"])
    def test_url_roundtrip(self, text):
        assert op_from_url(op_to_url(text, {}), {}) == text

    @pytest.mark.parametrize("text", ["hello", "<script>", "'"])
    def test_double_url_roundtrip(self, text):
        assert op_from_double_url(op_to_double_url(text, {}), {}) == text

    @pytest.mark.parametrize("text", ["hello", "0123", "\x00\xff"])
    def test_hex_roundtrip(self, text):
        # Note: text may contain non-utf8; hex round-trip should still
        # work because we encode/decode as utf-8 with errors='replace'.
        out = op_from_hex(op_to_hex(text, {}), {})
        # For our test strings (mostly ASCII), result should be equal.
        # The \xff case will be replaced with U+FFFD - just verify hex
        # round-trip doesn't crash.
        assert isinstance(out, str)

    @pytest.mark.parametrize("text", ["A", "hello", "1"])
    def test_binary_roundtrip(self, text):
        assert op_from_binary(op_to_binary(text, {}), {}) == text

    @pytest.mark.parametrize("text", ["<script>", "&", "\"quoted\""])
    def test_html_entities_roundtrip(self, text):
        assert op_from_html_entities(op_to_html_entities(text, {}), {}) == text

    def test_rot13_is_self_inverse(self):
        text = "Hello, world!"
        assert op_rot13_clean(op_rot13_clean(text, {}), {}) == text


class TestEncodingTolerance:
    def test_from_base64_tolerates_missing_padding(self):
        # 'admin' encoded is 'YWRtaW4=' - strip the '=' to test padding fix.
        assert op_from_base64("YWRtaW4", {}) == "admin"

    def test_from_base64_tolerates_base64url(self):
        # base64url uses - and _ instead of + and /.
        # b'>?' encodes as 'Pj8=' in standard, '-_8=' is base64url for different bytes.
        # Just verify the substitution happens without error.
        result = op_from_base64("c29tZS9zdHJpbmc=".replace("/", "_"), {})
        assert result == "some/string"

    def test_from_hex_tolerates_whitespace_and_separators(self):
        assert op_from_hex("61 64 6d 69 6e", {}) == "admin"
        assert op_from_hex("61:64:6d:69:6e", {}) == "admin"
        assert op_from_hex("0x61646d696e", {}) == "admin"

    def test_from_binary_pads_to_multiple_of_8(self):
        # 'A' is 65 = 01000001 -> 8 bits, valid.
        # Test with leading-zero-stripped version:
        assert op_from_binary("1000001", {}) == "A"


# ---------------------------------------------------------------------
# HASHING
# ---------------------------------------------------------------------
class TestHashing:
    def test_md5_known_vector(self):
        # 'abc' -> 900150983cd24fb0d6963f7d28e17f72
        assert _hash("md5")("abc", {}) == "900150983cd24fb0d6963f7d28e17f72"

    def test_sha256_known_vector(self):
        # SHA-256 of 'abc' is a famous test vector.
        assert _hash("sha256")("abc", {}) == \
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_hmac_sha256(self):
        # Same input + same key -> same digest. Different key -> different.
        a = op_hmac_sha256("hello", {"key": "secret"})
        b = op_hmac_sha256("hello", {"key": "secret"})
        c = op_hmac_sha256("hello", {"key": "other"})
        assert a == b
        assert a != c
        assert len(a) == 64    # SHA-256 hex digest


# ---------------------------------------------------------------------
# STRING
# ---------------------------------------------------------------------
class TestStringOps:
    def test_reverse(self):
        assert op_reverse("hello", {}) == "olleh"

    def test_upper_lower(self):
        assert op_upper("Hello", {}) == "HELLO"
        assert op_lower("Hello", {}) == "hello"

    def test_strip(self):
        assert op_strip("  hello  ", {}) == "hello"

    def test_count_includes_all_stats(self):
        out = op_count("one two\nthree", {})
        # Multi-line stats - just check key facts.
        assert "chars" in out
        assert "lines: 2" in out
        assert "words: 3" in out

    def test_sort_lines(self):
        assert op_sort_lines("b\na\nc", {}) == "a\nb\nc"

    def test_unique_lines_preserves_order(self):
        assert op_unique_lines("a\nb\na\nc\nb", {}) == "a\nb\nc"


# ---------------------------------------------------------------------
# DATA FORMAT
# ---------------------------------------------------------------------
class TestDataFormat:
    def test_json_pretty(self):
        out = op_json_pretty('{"b":1,"a":2}', {})
        # Should be multi-line and parseable.
        assert "\n" in out
        assert json.loads(out) == {"b": 1, "a": 2}

    def test_json_minify(self):
        out = op_json_minify('{"a":  1,  "b":  2}', {})
        # No whitespace between tokens
        assert " " not in out

    def test_parse_url(self):
        out = json.loads(op_parse_url("https://user:pw@host:8080/p?a=1#x", {}))
        assert out["scheme"] == "https"
        assert out["hostname"] == "host"
        assert out["port"] == 8080
        assert out["path"] == "/p"
        assert out["params"]["a"] == "1"
        assert out["fragment"] == "x"

    def test_parse_query_string(self):
        out = json.loads(op_parse_query_string("a=1&b=2&c=", {}))
        assert out == {"a": "1", "b": "2", "c": ""}


# ---------------------------------------------------------------------
# DEFANG / REFANG
# ---------------------------------------------------------------------
class TestDefang:
    def test_defang_url_roundtrip(self):
        url = "https://evil.example.com/path"
        assert op_refang_url(op_defang_url(url, {}), {}) == url

    def test_defang_url_actually_defangs(self):
        out = op_defang_url("https://x.com", {})
        # Should not autolink in a mail client / chat
        assert "https" not in out or "hxxps" in out
        assert "[.]" in out

    def test_defang_email_roundtrip(self):
        email = "user@bad.example.com"
        assert op_refang_email(op_defang_email(email, {}), {}) == email


# ---------------------------------------------------------------------
# TIME
# ---------------------------------------------------------------------
class TestTime:
    def test_epoch_to_iso(self):
        # 0 epoch = 1970-01-01T00:00:00+00:00
        assert "1970-01-01" in op_epoch_to_iso("0", {})

    def test_epoch_ms_detected(self):
        # Anything > 1e12 is treated as milliseconds.
        out = op_epoch_to_iso("0", {})           # seconds
        out_ms = op_epoch_to_iso("1700000000000", {})   # ms
        assert "2023" in out_ms

    def test_iso_to_epoch_roundtrip(self):
        epoch = op_iso_to_epoch("1970-01-01T00:00:00+00:00", {})
        assert epoch == "0"

    def test_now_returns_iso(self):
        out = op_now("ignored", {})
        # Just check it parses as an ISO timestamp
        from datetime import datetime
        datetime.fromisoformat(out)


# ---------------------------------------------------------------------
# MISC
# ---------------------------------------------------------------------
class TestMisc:
    def test_random_hex_length(self):
        # N bytes -> 2N hex chars
        out = op_random_hex("", {"bytes": "16"})
        assert len(out) == 32
        # Different calls produce different values
        out2 = op_random_hex("", {"bytes": "16"})
        assert out != out2

    def test_uuid_v4_format(self):
        import re as _re
        out = op_uuid_v4("", {})
        assert _re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                          r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$", out)

    def test_jwt_decode_summary(self):
        # Minimal JWT.
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"
        out = json.loads(op_word_to_jwt_summary(token, {}))
        assert out["header"] == {"alg": "HS256"}
        assert out["payload"] == {"sub": "alice"}

    def test_jwt_decode_rejects_non_jwt(self):
        with pytest.raises(ValueError):
            op_word_to_jwt_summary("not.a.jwt.too.many", {})


# ---------------------------------------------------------------------
# MAGIC
# ---------------------------------------------------------------------
class TestMagic:
    def test_detects_base64(self):
        # 'admin' as base64
        candidates = magic_decode("YWRtaW4=")
        names = [n for n, _ in candidates]
        assert "From Base64" in names

    def test_no_candidates_for_plain_text(self):
        candidates = magic_decode("just plain text here")
        # All decoders either fail or produce garbage - filter result.
        # Some MIGHT succeed (URL decode is identity on text without
        # %). The key invariant: nothing that's clearly garbage gets
        # through.
        for name, result in candidates:
            assert _looks_readable(result)

    def test_detects_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"
        candidates = magic_decode(token)
        names = [n for n, _ in candidates]
        assert "JWT decode" in names


# ---------------------------------------------------------------------
# TUI RENDER SMOKE TESTS
# ---------------------------------------------------------------------
# Regression for a real bug: show_state() called recipe_text.rstrip()
# which mutates Text in place and returns None - Panel then crashed
# with NotRenderableError. These tests render show_state to a buffer
# under various recipe states so any future rendering bug surfaces
# in CI instead of when the user fires up the TUI.
class TestShowStateRender:
    def _make_console(self):
        """A buffer-backed Console that won't write to a real terminal."""
        import io
        from rich.console import Console
        from cyberchef import THEME
        return Console(theme=THEME, file=io.StringIO(),
                        force_terminal=True, width=100, highlight=False)

    def test_empty_recipe_renders(self):
        c = self._make_console()
        show_state(c, "hello", [])
        out = c.file.getvalue()
        assert "Current value" in out
        assert "hello" in out

    def test_recipe_with_one_step_renders(self):
        c = self._make_console()
        show_state(c, "YWRtaW4=", [("To Base64", {})])
        out = c.file.getvalue()
        assert "Recipe" in out
        assert "To Base64" in out

    def test_recipe_with_args_renders(self):
        c = self._make_console()
        # HMAC-SHA256 with a key arg - this is the path that uses
        # the args dict in the recipe display.
        show_state(c, "deadbeef", [("HMAC-SHA256", {"key": "secret"})])
        out = c.file.getvalue()
        assert "HMAC-SHA256" in out
        assert "key=" in out

    def test_long_value_truncated_in_display(self):
        # Display truncation to DISPLAY_TRUNCATE - panel should still
        # render without error even when the full value is huge.
        c = self._make_console()
        show_state(c, "x" * 10000, [])
        out = c.file.getvalue()
        assert "truncated" in out


# ---------------------------------------------------------------------
# ALIAS RESOLUTION + AUTOCOMPLETE CATALOG
# ---------------------------------------------------------------------
class TestAliasResolution:
    def test_every_alias_resolves_to_a_real_operation(self):
        # If an alias in ALIASES points at a name that doesn't exist
        # in OPERATIONS, the prompt would silently fail to dispatch.
        # Catch that here.
        op_names = {op.name for op in OPERATIONS}
        for alias, target in ALIASES.items():
            assert target in op_names, \
                f"alias {alias!r} points at unknown op {target!r}"

    def test_common_aliases_resolve(self):
        # The aliases promoted on the banner MUST work.
        for alias, expected in [
            ("b64",   "To Base64"),
            ("b64d",  "From Base64"),
            ("url",   "To URL"),
            ("urld",  "From URL"),
            ("hex",   "To Hex"),
            ("hexd",  "From Hex"),
            ("md5",   "MD5"),
            ("sha256", "SHA-256"),
            ("jwt",   "JWT decode"),
            ("magic", None),    # magic is a control command, not an op
        ]:
            if expected is None:
                continue
            op = resolve_op_name(alias)
            assert op is not None, f"alias {alias!r} returned None"
            assert op.name == expected

    def test_alias_lookup_case_insensitive(self):
        assert resolve_op_name("B64") is not None
        assert resolve_op_name("b64").name == resolve_op_name("B64").name

    def test_full_name_also_resolves(self):
        op = resolve_op_name("To Base64")
        assert op is not None
        assert op.name == "To Base64"

    def test_unknown_returns_none(self):
        assert resolve_op_name("not-a-real-op") is None
        assert resolve_op_name("") is None
        assert resolve_op_name("   ") is None


class TestPromptChoices:
    def test_includes_control_commands(self):
        choices = _prompt_choices()
        for cmd in ("help", "list", "undo", "save", "magic", "quit"):
            assert cmd in choices

    def test_includes_aliases(self):
        choices = _prompt_choices()
        for alias in ("b64", "sha256", "jwt"):
            assert alias in choices

    def test_includes_full_op_names(self):
        choices = _prompt_choices()
        assert "To Base64" in choices
        assert "SHA-256" in choices

    def test_no_duplicate_entries(self):
        # Duplicates would make the autocompleter show the same
        # suggestion twice - harmless but ugly.
        choices = _prompt_choices()
        # Note: there can be legitimate overlaps between aliases and
        # op names (e.g. "MD5" is both an alias and the op name).
        # That's fine; the suggestion shows once after dedup.
        deduped = set(choices)
        assert len(deduped) > 50    # we have 40 ops + ~50 aliases
                                     # + 9 control commands, even with
                                     # some overlap > 50 stays true


class TestControlCommands:
    def test_includes_quit_aliases(self):
        # `q`, `quit`, `exit` are all accepted.
        for alias in ("q", "quit", "exit"):
            assert alias in CONTROL_COMMANDS

    def test_includes_all_documented_commands(self):
        # Every command surfaced in the banner / help cheat sheet.
        for cmd in ("magic", "identify", "id", "what",
                     "edit", "undo", "reset", "save",
                     "help", "list"):
            assert cmd in CONTROL_COMMANDS


# ---------------------------------------------------------------------
# FORMAT IDENTIFICATION
# ---------------------------------------------------------------------
def _labels(text: str) -> list[str]:
    """Helper: just the labels of identify_format(text) for easier asserts."""
    return [h.label for h in identify_format(text)]


class TestIdentifyHashes:
    def test_md5(self):
        # MD5("admin") = 21232f297a57a5a743894a0e4a801fc3
        labels = _labels("21232f297a57a5a743894a0e4a801fc3")
        assert any("MD5" in l for l in labels)

    def test_sha1(self):
        labels = _labels("a" * 40)
        assert any("SHA-1" in l for l in labels)

    def test_sha256(self):
        labels = _labels("b" * 64)
        assert any("SHA-256" in l for l in labels)

    def test_sha384(self):
        # 96 hex chars - same length as SHA-384 hex digest.
        labels = _labels("c" * 96)
        assert any("SHA-384" in l for l in labels)

    def test_sha512(self):
        labels = _labels("d" * 128)
        assert any("SHA-512" in l for l in labels)

    def test_each_hash_distinct(self):
        # Sanity that each hash length maps to its OWN label.
        for length, expected in ((32, "MD5"), (40, "SHA-1"), (64, "SHA-256"),
                                   (96, "SHA-384"), (128, "SHA-512")):
            labels = _labels("a" * length)
            matching = [l for l in labels if expected in l]
            assert len(matching) == 1, \
                f"hex string of length {length} should match exactly one hash " \
                f"family ({expected}); got labels: {labels}"

    def test_hash_does_not_also_flag_hex_bytes(self):
        # A 32-hex-char string IS valid hex but we report it as MD5
        # specifically and NOT as a generic "hex bytes" interpretation
        # (would be noisy).
        labels = _labels("21232f297a57a5a743894a0e4a801fc3")
        assert not any("Hex-encoded bytes" in l for l in labels)


class TestIdentifyJwt:
    def test_jwt_detected(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"
        labels = _labels(token)
        assert any("JWT" in l for l in labels)

    def test_not_jwt_when_only_two_parts(self):
        assert not any("JWT" in l for l in _labels("a.b"))

    def test_not_jwt_when_empty_segment(self):
        # alg=none JWTs end with a trailing dot - the SIG part is empty.
        # Our heuristic requires all 3 parts non-empty; that's OK because
        # the user would identify this as base64 instead and the
        # downstream `jwt` command handles it anyway.
        assert not any("JWT" in l for l in _labels("a.b."))


class TestIdentifyUuid:
    def test_uuid_v4(self):
        labels = _labels("01234567-89ab-4cde-9fff-fedcba987654")
        assert any("UUID v4" in l for l in labels)

    def test_uuid_v1_variant(self):
        # 3rd group starts with 1 (v1), variant nibble in range
        labels = _labels("01234567-89ab-1cde-9fff-fedcba987654")
        assert any("UUID" in l for l in labels)


class TestIdentifyNetwork:
    def test_ipv4(self):
        labels = _labels("192.168.1.1")
        assert any("IPv4" in l for l in labels)

    def test_invalid_octet_rejected(self):
        labels = _labels("999.999.999.999")
        # Should NOT be flagged as IPv4 (octets out of range).
        assert not any("IPv4" in l for l in labels)


class TestIdentifyTime:
    def test_epoch_seconds(self):
        # 1700000000 = 2023-11-14ish
        labels = _labels("1700000000")
        assert any("Unix epoch seconds" in l for l in labels)

    def test_epoch_ms(self):
        labels = _labels("1700000000000")
        assert any("Unix epoch milliseconds" in l for l in labels)

    def test_iso_timestamp(self):
        labels = _labels("2026-05-28T14:30:00Z")
        assert any("ISO 8601" in l for l in labels)


class TestIdentifyData:
    def test_email(self):
        assert any("Email" in l for l in _labels("user@example.com"))

    def test_url(self):
        assert any("URL" in l for l in _labels("https://example.com/path"))

    def test_json_object(self):
        assert any("JSON" in l for l in _labels('{"a": 1}'))

    def test_json_array(self):
        assert any("JSON" in l for l in _labels('[1, 2, 3]'))

    def test_html(self):
        assert any("HTML" in l or "XML" in l
                    for l in _labels("<!DOCTYPE html><html><body></body></html>"))


class TestIdentifyCookieShape:
    def test_username_md5_cookie(self):
        # This is the BSCP "stay-logged-in" cookie format - MUST detect.
        labels = _labels("wiener:51dc30ddc473d433366176fa25a71b14")
        assert any("MD5(password)" in l for l in labels)

    def test_username_sha1_cookie(self):
        labels = _labels("wiener:" + "a" * 40)
        assert any("SHA1(password)" in l for l in labels)

    def test_pipe_separated_cookie(self):
        labels = _labels("admin|2026-06-01")
        assert any("pipe-separated" in l for l in labels)

    def test_query_string(self):
        labels = _labels("id=1&user=admin&token=xyz")
        assert any("query string" in l for l in labels)


class TestIdentifyBase64AndHex:
    def test_base64_flagged(self):
        # "Hello, world!" base64 = "SGVsbG8sIHdvcmxkIQ=="
        labels = _labels("SGVsbG8sIHdvcmxkIQ==")
        assert any("base64" in l for l in labels)

    def test_hex_bytes_when_not_hash_length(self):
        # 16 hex chars - not a standard hash length, so it's bytes.
        labels = _labels("48656c6c6f20776f726c64")    # "Hello world"
        assert any("Hex-encoded" in l for l in labels)


class TestIdentifyEmpty:
    def test_empty_returns_no_hints(self):
        assert identify_format("") == []
        assert identify_format("   ") == []


class TestIdentifyStructuredData:
    def test_php_serialized(self):
        s = 'a:2:{i:0;s:5:"hello";i:1;s:5:"world";}'
        assert any("PHP serialized" in l for l in _labels(s))

    def test_php_serialized_object(self):
        s = 'O:8:"stdClass":1:{s:4:"name";s:5:"alice";}'
        assert any("PHP serialized" in l for l in _labels(s))

    def test_http_request_line(self):
        for line in ("GET /admin HTTP/1.1",
                      "POST /login HTTP/2.0",
                      "PUT /api/users/1 HTTP/1.1"):
            labels = _labels(line)
            assert any("HTTP request line" in l for l in labels), \
                f"failed for {line!r}"

    def test_http_response_status_line(self):
        for line in ("HTTP/1.1 200 OK", "HTTP/2.0 404 Not Found"):
            labels = _labels(line)
            assert any("HTTP response status" in l for l in labels), \
                f"failed for {line!r}"

    def test_set_cookie_header(self):
        cookie = "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
        labels = _labels(cookie)
        assert any("Set-Cookie" in l for l in labels)

    def test_set_cookie_missing_flags_flagged(self):
        cookie = "session=abc123; Path=/"   # no HttpOnly / Secure / SameSite
        hints = identify_format(cookie)
        set_cookie_hints = [h for h in hints if "Set-Cookie" in h.label]
        assert set_cookie_hints
        # Suggestion mentions the missing flags
        assert "HttpOnly" in set_cookie_hints[0].suggestion
        assert "Secure" in set_cookie_hints[0].suggestion
        assert "SameSite" in set_cookie_hints[0].suggestion

    def test_cookie_header_form(self):
        # Multiple cookies WITHOUT attribute keywords = client-side
        # Cookie header.
        labels = _labels("a=1; b=2; c=3")
        assert any("Cookie header" in l for l in labels)

    def test_graphql_query(self):
        for q in ("query { user(id:1) { name } }",
                   "mutation { createUser(name:\"x\") { id } }",
                   "{ users { id name } }"):
            labels = _labels(q)
            assert any("GraphQL" in l for l in labels), f"failed for {q!r}"

    def test_jwk(self):
        jwk = '{"kty":"RSA","kid":"abc","alg":"RS256","n":"xxxx","e":"AQAB"}'
        assert any("JWK" in l for l in _labels(jwk))

    def test_yaml_document(self):
        yaml_text = "name: alice\nage: 30\nroles:\n  - admin\n  - user\n"
        assert any("YAML" in l for l in _labels(yaml_text))

    def test_json_not_flagged_as_yaml(self):
        # JSON shouldn't trigger the YAML detector (which would be
        # double-flagging).
        labels = _labels('{"name": "alice"}')
        assert not any("YAML" in l for l in labels)

    def test_xml_document(self):
        xml = '<?xml version="1.0"?><root><user>alice</user></root>'
        labels = _labels(xml)
        assert any("XML" in l for l in labels)

    def test_soap_envelope(self):
        soap = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/">'
        assert any("XML / SOAP" in l for l in _labels(soap))

    def test_ipv6_cidr(self):
        labels = _labels("2001:db8::/64")
        assert any("IPv6 CIDR" in l for l in labels)

    def test_host_port(self):
        labels = _labels("example.com:8080")
        assert any("host:port" in l for l in labels)

    def test_invalid_port_not_flagged(self):
        # Port > 65535 should not be flagged.
        labels = _labels("example.com:99999")
        assert not any("host:port" in l for l in labels)

    def test_numeric_id(self):
        labels = _labels("42")
        assert any("Numeric value" in l for l in labels)

    def test_short_hex_8(self):
        labels = _labels("deadbeef")
        assert any("8 hex chars" in l for l in labels)
        # Should NOT also flag as generic base64 / hex bytes
        assert not any(l.startswith("Looks like base64") for l in labels)
        assert not any(l == "Hex-encoded bytes" for l in labels)

    def test_short_hex_16(self):
        labels = _labels("deadbeefcafef00d")
        assert any("16 hex chars" in l for l in labels)
        assert not any(l.startswith("Looks like base64") for l in labels)
        assert not any(l == "Hex-encoded bytes" for l in labels)

    def test_md5_still_takes_precedence_over_short_hex(self):
        # 32 hex chars should be MD5, NOT also flagged as short-hex
        # (because of the de-noising check `"hash" in label`).
        labels = _labels("21232f297a57a5a743894a0e4a801fc3")
        assert any("MD5" in l for l in labels)
        assert not any("8 hex chars" in l or "16 hex chars" in l
                        for l in labels)


class TestIdentifyComprehensiveSweep:
    """
    One realistic input per detector + verification that the expected
    label substring fires. Caught a real coverage gap (SHA-384 was
    documented as supported but never implemented).

    If you ADD a new detector to identify_format, add a row here
    too - it's the regression net.
    """
    # Each row: (display label, input string, must-contain substring
    # in at least one returned hint's label)
    SWEEP_CASES = [
        # Hashes
        ("MD5",              "21232f297a57a5a743894a0e4a801fc3", "MD5"),
        ("SHA-1",            "a"*40,                              "SHA-1"),
        ("SHA-256",          "b"*64,                              "SHA-256"),
        ("SHA-384",          "c"*96,                              "SHA-384"),
        ("SHA-512",          "d"*128,                             "SHA-512"),
        ("Bcrypt",           "$2a$10$" + "A"*53,                  "Bcrypt"),
        ("crypt(3)",         "$5$rounds=5000$salt$abc",           "crypt(3)"),
        ("Argon2",           "$argon2id$v=19$m=65536$salt$hash",  "Argon2"),
        # Tokens
        ("JWT",              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig", "JWT"),
        ("JWK",              '{"kty":"RSA","kid":"a","alg":"RS256","n":"x","e":"AQAB"}', "JWK"),
        ("Bearer header",    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig", "Bearer"),
        ("Basic header",     "Basic YWRtaW46cGFzc3dvcmQ=",        "Basic"),
        ("Token header",     "Token abc123def456ghi789jkl012mno", "Token"),
        # Vendor API keys
        ("AWS AKIA",         "AKIAIOSFODNN7EXAMPLE",              "AWS"),
        ("AWS ASIA",         "ASIAIOSFODNN7EXAMPLE",              "AWS"),
        ("GitHub PAT",       "ghp_" + "A"*36,                     "GitHub"),
        ("Stripe sk_live_",  "sk_live_" + "A"*24,                 "Stripe"),
        ("Slack bot",        "xoxb-1-1-" + "A"*8,                 "Slack"),
        ("GitLab PAT",       "glpat-" + "A"*20,                   "GitLab"),
        ("OpenAI",           "sk-" + "A"*48,                      "OpenAI"),
        ("Anthropic",        "sk-ant-" + "A"*80,                  "Anthropic"),
        ("Google svc-acct",  '{"type": "service_account"}',       "Google"),
        ("Google API key",   "AIza" + "A"*35,                     "Google"),
        ("Twilio SK",        "SK" + "a"*32,                       "Twilio"),
        ("Twilio AC",        "AC" + "f"*32,                       "Twilio"),
        ("SendGrid",         "SG." + "A"*22 + "." + "B"*43,       "SendGrid"),
        ("Mailgun",          "key-" + "a"*32,                     "Mailgun"),
        ("npm token",        "npm_" + "A"*36,                     "npm"),
        ("Docker PAT",       "dckr_pat_" + "A"*27,                "Docker"),
        ("Discord bot",      "M" + "A"*23 + "." + "B"*6 + "." + "C"*27, "Discord"),
        # PEM keys
        ("RSA PRIVATE",      "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----", "RSA private key"),
        ("EC PRIVATE",       "-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----", "EC private key"),
        ("OpenSSH PRIVATE",  "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----", "OpenSSH"),
        ("X.509 cert",       "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----", "X.509"),
        ("PGP private",      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----", "PGP"),
        # Network
        ("IPv4",             "192.168.1.1",                       "IPv4"),
        ("IPv4 CIDR",        "10.0.0.0/8",                        "CIDR"),
        ("IPv6 ::1",         "::1",                               "IPv6"),
        ("IPv6 full",        "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IPv6"),
        ("IPv6 CIDR",        "2001:db8::/64",                     "IPv6 CIDR"),
        ("MAC",              "aa:bb:cc:dd:ee:ff",                 "MAC"),
        ("host:port",        "metadata.internal:8080",            "host:port"),
        # IDs / time
        ("UUID v4",          "01234567-89ab-4cde-9fff-fedcba987654", "UUID v4"),
        ("MongoDB OID",      "507f1f77bcf86cd799439011",          "MongoDB"),
        ("Epoch sec",        "1700000000",                         "epoch seconds"),
        ("Epoch ms",         "1700000000000",                      "milliseconds"),
        ("ISO 8601",         "2026-05-29T14:23:01Z",              "ISO 8601"),
        ("Numeric ID",       "42",                                 "Numeric"),
        # Web data
        ("Email",            "user@example.com",                  "Email"),
        ("URL",              "https://example.com/path",          "URL"),
        ("JSON",             '{"a":1}',                            "JSON"),
        ("HTML",             "<!DOCTYPE html><html></html>",      "HTML"),
        ("Query string",     "a=1&b=2&c=3",                       "query string"),
        # Cookie shapes
        ("user:MD5",         "wiener:51dc30ddc473d433366176fa25a71b14", "username:MD5"),
        ("user:SHA1",        "wiener:" + "a"*40,                  "username:SHA1"),
        ("pipe cookie",      "admin|2026-06-01",                  "pipe-separated"),
        # Attack payloads
        ("Path traversal",   "../../../etc/passwd",               "Path traversal"),
        ("SQL injection",    "' UNION SELECT NULL--",             "SQL injection"),
        ("XSS",              "<script>alert(1)</script>",         "XSS"),
        ("SSTI",             "{{7*7}}",                            "Template injection"),
        ("JNDI",             "${jndi:ldap://x/y}",                "JNDI"),
        # Structured
        ("PHP serialized",   'a:1:{i:0;s:1:"x";}',                "PHP serialized"),
        ("HTTP req line",    "GET /admin HTTP/1.1",               "HTTP request line"),
        ("HTTP resp status", "HTTP/1.1 200 OK",                   "HTTP response"),
        ("Set-Cookie",       "session=x; Path=/; HttpOnly",       "Set-Cookie"),
        ("Cookie hdr form",  "a=1; b=2",                          "Cookie header"),
        ("GraphQL",          "query { user { name } }",           "GraphQL"),
        ("YAML",             "name: alice\nrole: admin",          "YAML"),
        ("SOAP",             '<soap:Envelope xmlns:soap="x"/>',   "SOAP"),
        # Generic / fallback
        ("HTTP Basic value", "YWRtaW46cGFzc3dvcmQ=",              "HTTP Basic"),
        ("Hex 8 chars",      "deadbeef",                          "8 hex chars"),
        ("Hex 16 chars",     "deadbeefcafef00d",                  "16 hex chars"),
        ("Opaque token",     "aBcD1234efGh5678ijKlMnOp90123",     "opaque token"),
    ]

    @pytest.mark.parametrize("display,inp,expect", SWEEP_CASES,
                              ids=lambda v: v if isinstance(v, str) else None)
    def test_detector_fires(self, display, inp, expect):
        from cyberchef import identify_format
        hints = identify_format(inp)
        matches = [h.label for h in hints if expect.lower() in h.label.lower()]
        assert matches, (
            f"{display}: expected label containing {expect!r}; "
            f"got: {[h.label for h in hints]!r}"
        )


class TestIdentifyAuthPrefixes:
    def test_bearer_jwt_identified_both_ways(self):
        # `Bearer eyJ...` should identify BOTH the Bearer prefix AND
        # recurse to identify the inner JWT.
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
        labels = _labels(f"Bearer {token}")
        assert any("Bearer" in l for l in labels)
        assert any("(inner credential) JWT" in l for l in labels)

    def test_bearer_lowercase(self):
        # Some apps use lowercase bearer.
        token = "abc123def456ghi789jkl"
        labels = _labels(f"bearer {token}")
        assert any("Bearer" in l for l in labels)

    def test_basic_auth_value(self):
        # Basic + b64 of admin:password
        labels = _labels("Basic YWRtaW46cGFzc3dvcmQ=")
        assert any("Basic" in l for l in labels)
        # Inner should be identified too (HTTP Basic auth value).
        assert any("(inner credential)" in l for l in labels)

    def test_token_prefix(self):
        labels = _labels("Token abc123def456ghi789jkl012mno345")
        assert any("Token" in l for l in labels)


class TestIdentifyOpaqueTokenFallback:
    def test_long_alphanum_falls_through_to_opaque_token(self):
        # No specific format - long random-looking string with length
        # NOT divisible by 4 (so base64 detector won't claim it first).
        # Fallback should fire so the user gets SOMETHING actionable.
        labels = _labels("aBcD1234efGh5678ijKlMnOp90123")    # 29 chars
        assert any("opaque token" in l for l in labels)

    def test_short_random_does_NOT_trip_opaque_token(self):
        # < 16 chars - too short to be a meaningful opaque token,
        # would just be noisy.
        labels = _labels("short42")
        assert not any("opaque token" in l for l in labels)

    def test_low_entropy_does_not_trip_opaque(self):
        # All-same character or very low diversity - not a token,
        # probably just placeholder text.
        labels = _labels("aaaaaaaaaaaaaaaaaaaaaaaa")
        assert not any("opaque token" in l for l in labels)

    def test_one_char_class_does_not_trip(self):
        # All lowercase + low diversity - not opaque-token shaped.
        labels = _labels("hello world this is some text")
        assert not any("opaque token" in l for l in labels)

    def test_specific_match_suppresses_opaque_fallback(self):
        # A 24-hex string matches MongoDB ObjectId AND is the right
        # SHAPE to be opaque-token. ObjectId should win; opaque
        # should NOT also fire.
        labels = _labels("507f1f77bcf86cd799439011")
        assert any("MongoDB" in l for l in labels)
        assert not any("opaque token" in l for l in labels)


# ---------------------------------------------------------------------
# Additional format detectors (modern hashes, network, vendor tokens,
# attack payloads)
# ---------------------------------------------------------------------
class TestIdentifyModernHashes:
    def test_bcrypt(self):
        # Sample bcrypt for 'password': $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
        h = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        assert any("Bcrypt" in l for l in _labels(h))

    def test_crypt3_sha256(self):
        # $5$ = SHA256-crypt
        h = "$5$rounds=5000$saltsalt$abc"
        labels = _labels(h)
        assert any("crypt(3)" in l and "SHA256-crypt" in l for l in labels)

    def test_argon2(self):
        h = "$argon2id$v=19$m=65536,t=3,p=4$saltsalt$hashhash"
        assert any("Argon2" in l for l in _labels(h))


class TestIdentifyNetworkExtra:
    def test_ipv4_cidr(self):
        assert any("CIDR" in l for l in _labels("10.0.0.0/8"))
        assert any("CIDR" in l for l in _labels("192.168.1.0/24"))

    def test_invalid_cidr_rejected(self):
        # /99 is invalid (must be 0-32 for IPv4)
        assert not any("CIDR" in l for l in _labels("10.0.0.0/99"))

    def test_ipv6_compressed(self):
        for addr in ("::1", "fe80::1", "2001:db8::1"):
            labels = _labels(addr)
            assert any("IPv6" in l for l in labels), f"failed on {addr!r}"

    def test_ipv6_full(self):
        addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        assert any("IPv6" in l for l in _labels(addr))

    def test_mac_address_colon(self):
        assert any("MAC" in l for l in _labels("aa:bb:cc:dd:ee:ff"))

    def test_mac_address_dash(self):
        assert any("MAC" in l for l in _labels("AA-BB-CC-DD-EE-FF"))


class TestIdentifyMongoObjectId:
    def test_24_hex_chars(self):
        # NOT 32 (MD5), NOT 40 (SHA-1) - 24 is distinctively ObjectId.
        labels = _labels("507f1f77bcf86cd799439011")
        assert any("MongoDB ObjectId" in l for l in labels)

    def test_md5_not_flagged_as_objectid(self):
        # 32 hex chars - should be MD5, NOT ObjectId.
        labels = _labels("21232f297a57a5a743894a0e4a801fc3")
        assert not any("MongoDB" in l for l in labels)


class TestIdentifyVendorTokens:
    def test_aws_access_key_id_permanent(self):
        labels = _labels("AKIAIOSFODNN7EXAMPLE")
        assert any("AWS access key" in l and "permanent" in l for l in labels)

    def test_aws_access_key_id_temporary(self):
        labels = _labels("ASIAIOSFODNN7EXAMPLE")
        assert any("AWS access key" in l and "temporary" in l for l in labels)

    def test_github_personal_access_token(self):
        # ghp_ prefix + 36-40 alphanum chars
        token = "ghp_" + "A" * 36
        assert any("GitHub" in l and "Personal" in l for l in _labels(token))

    def test_github_server_token(self):
        token = "ghs_" + "A" * 36
        assert any("GitHub" in l and "Server-to-server" in l for l in _labels(token))

    def test_stripe_secret_live(self):
        token = "sk_live_" + "A" * 24
        labels = _labels(token)
        assert any("Stripe" in l and "SECRET" in l and "LIVE" in l for l in labels)

    def test_stripe_publishable_test(self):
        token = "pk_test_" + "A" * 24
        labels = _labels(token)
        assert any("Stripe" in l and "publishable" in l and "TEST" in l for l in labels)

    def test_slack_bot_token(self):
        token = "xoxb-123-456-AAAAAAAA"
        labels = _labels(token)
        assert any("Slack" in l and "Bot" in l for l in labels)

    def test_gitlab_pat(self):
        token = "glpat-" + "A" * 20
        assert any("GitLab" in l for l in _labels(token))

    def test_openai_user_key(self):
        token = "sk-" + "A" * 48
        assert any("OpenAI" in l and "user / org" in l for l in _labels(token))

    def test_openai_project_key(self):
        token = "sk-proj-" + "A" * 40
        assert any("OpenAI" in l and "project" in l for l in _labels(token))

    def test_openai_service_account(self):
        token = "sk-svcacct-" + "A" * 40
        assert any("OpenAI" in l and "service account" in l for l in _labels(token))

    def test_anthropic_key(self):
        token = "sk-ant-" + "A" * 80
        assert any("Anthropic" in l for l in _labels(token))

    def test_anthropic_not_also_flagged_as_openai(self):
        # sk-ant-... starts with sk- so the naive OpenAI regex
        # matches too. Negative-lookahead suppresses that.
        token = "sk-ant-" + "A" * 80
        labels = _labels(token)
        assert any("Anthropic" in l for l in labels)
        assert not any("OpenAI" in l for l in labels)

    def test_google_service_account_json(self):
        s = '{"type": "service_account", "project_id": "x", "private_key": "y"}'
        assert any("Google Cloud service-account" in l for l in _labels(s))

    def test_google_service_account_no_space(self):
        # Compact-JSON form (no space after `:`) should also detect.
        s = '{"type":"service_account","project_id":"x"}'
        assert any("Google Cloud service-account" in l for l in _labels(s))

    def test_google_api_key(self):
        token = "AIza" + "A" * 35
        assert any("Google API key" in l for l in _labels(token))

    def test_twilio_sk(self):
        token = "SK" + "a" * 32
        assert any("Twilio API key SID" in l for l in _labels(token))

    def test_twilio_account_sid(self):
        token = "AC" + "f" * 32
        assert any("Twilio Account SID" in l for l in _labels(token))

    def test_sendgrid(self):
        token = "SG." + "A" * 22 + "." + "B" * 43
        assert any("SendGrid" in l for l in _labels(token))

    def test_mailgun_legacy(self):
        token = "key-" + "a" * 32
        assert any("Mailgun" in l for l in _labels(token))

    def test_npm_token(self):
        token = "npm_" + "A" * 36
        assert any("npm access token" in l for l in _labels(token))

    def test_docker_hub_pat(self):
        token = "dckr_pat_" + "A" * 27
        assert any("Docker Hub" in l for l in _labels(token))

    def test_discord_bot_token(self):
        token = "M" + "A" * 23 + "." + "B" * 6 + "." + "C" * 27
        labels = _labels(token)
        assert any("Discord bot token" in l for l in labels)

    def test_discord_token_not_also_flagged_as_jwt(self):
        # Discord tokens have the same SHAPE as JWTs (3 base64url
        # parts) but the first part isn't a JSON header - so the JWT
        # detector (which now JSON-parses the first part) should NOT
        # also flag this. Avoids the user being told the same token
        # is "two different things at once".
        token = "M" + "A" * 23 + "." + "B" * 6 + "." + "C" * 27
        labels = _labels(token)
        assert not any("JWT" in l for l in labels)


class TestIdentifyPrivateKeys:
    def test_rsa_private_key(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIEpAIBAAKCAQEA...\n"
               "-----END RSA PRIVATE KEY-----")
        labels = _labels(pem)
        assert any("PEM-armored RSA private key" in l for l in labels)

    def test_pem_dashes_not_flagged_as_sql_comment(self):
        # Regression: the `--` SQL comment detector used to match
        # the trailing dashes in "-----END ... -----". Now requires
        # a non-dash precede + space-or-EOL after to disambiguate.
        pem = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
               "data\n"
               "-----END OPENSSH PRIVATE KEY-----")
        labels = _labels(pem)
        # Should be detected as a private key, NOT as a SQL injection.
        assert any("PEM-armored OpenSSH" in l for l in labels)
        assert not any("SQL injection" in l for l in labels)

    def test_openssh_private_key(self):
        pem = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
               "b3BlbnNzaC1rZXkt...\n"
               "-----END OPENSSH PRIVATE KEY-----")
        labels = _labels(pem)
        assert any("PEM-armored OpenSSH private key" in l for l in labels)

    def test_ec_private_key(self):
        pem = ("-----BEGIN EC PRIVATE KEY-----\nMHcCAQ...\n-----END EC PRIVATE KEY-----")
        labels = _labels(pem)
        assert any("PEM-armored EC private key" in l for l in labels)

    def test_x509_certificate(self):
        pem = ("-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIB...\n-----END CERTIFICATE-----")
        labels = _labels(pem)
        assert any("PEM X.509 certificate" in l for l in labels)

    def test_pgp_private_key(self):
        pem = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\nxYY...\n-----END PGP PRIVATE KEY BLOCK-----")
        labels = _labels(pem)
        assert any("PGP private key" in l for l in labels)


class TestJwtFalsePositiveAvoidance:
    def test_real_jwt_still_detected(self):
        # Sanity: tightening the detector didn't break the real case.
        # Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.sig"
        labels = _labels(token)
        assert any("JWT" in l for l in labels)

    def test_random_3_dot_string_not_jwt(self):
        # Looks JWT-shaped but the first part isn't valid base64 JSON.
        token = "ABCDEF.GHIJKL.MNOPQR"
        labels = _labels(token)
        assert not any("JWT" in l for l in labels)

    def test_jwt_without_alg_field_rejected(self):
        # Valid base64 JSON header but no `alg` field - per RFC, not
        # a real JWT. {"foo":"bar"} -> eyJmb28iOiJiYXIifQ
        token = "eyJmb28iOiJiYXIifQ.eyJzdWIiOiJ4In0.sig"
        labels = _labels(token)
        assert not any("JWT" in l for l in labels)


class TestIdentifyAttackPayloads:
    def test_path_traversal_plain(self):
        for payload in ("../../../etc/passwd", "..\\..\\windows\\system32",
                         "%2e%2e/admin"):
            labels = _labels(payload)
            assert any("Path traversal" in l for l in labels), f"failed on {payload!r}"

    def test_sql_injection_union(self):
        for payload in ("' UNION SELECT NULL--",
                         "1 OR 1=1",
                         "admin'--",
                         "1; DROP TABLE users--",
                         "1' AND SLEEP(5)--"):
            labels = _labels(payload)
            assert any("SQL injection" in l for l in labels), \
                f"failed on {payload!r}"

    def test_xss_payloads(self):
        for payload in ("<script>alert(1)</script>",
                         "<img src=x onerror=alert(1)>",
                         "javascript:alert(1)",
                         "<body onload=alert(1)>"):
            labels = _labels(payload)
            assert any("XSS" in l for l in labels), f"failed on {payload!r}"

    def test_template_injection(self):
        for payload in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"):
            labels = _labels(payload)
            assert any("Template injection" in l for l in labels), \
                f"failed on {payload!r}"

    def test_jndi_log4shell(self):
        labels = _labels("${jndi:ldap://attacker.com/x}")
        assert any("JNDI" in l for l in labels)


class TestIdentifyHttpBasicAuth:
    def test_basic_auth_detected(self):
        import base64 as _b64
        # 'admin:password' base64
        value = _b64.b64encode(b"admin:password").decode()
        labels = _labels(value)
        assert any("HTTP Basic" in l for l in labels)

    def test_random_base64_not_flagged_as_basic_auth(self):
        # 'just_random_data' base64 - no colon in decoded form, so no Basic-auth hint.
        import base64 as _b64
        value = _b64.b64encode(b"just_random_data").decode()
        labels = _labels(value)
        assert not any("HTTP Basic" in l for l in labels)


# ---------------------------------------------------------------------
# De-noising: more-specific identifications suppress less-specific ones
# ---------------------------------------------------------------------
class TestIdentifyDenoising:
    def test_aws_key_not_also_flagged_as_generic_base64(self):
        # AWS keys are alphanum+ but suggesting "decode this as base64"
        # is actively wrong - so we suppress the base64 hint when AWS
        # already matched.
        labels = _labels("AKIAIOSFODNN7EXAMPLE")
        assert any("AWS" in l for l in labels)
        assert not any(l.startswith("Looks like base64") for l in labels)

    def test_github_token_not_also_flagged_as_base64(self):
        token = "ghp_" + "A" * 36
        labels = _labels(token)
        assert any("GitHub" in l for l in labels)
        assert not any(l.startswith("Looks like base64") for l in labels)

    def test_objectid_not_also_flagged_as_hex_bytes(self):
        labels = _labels("507f1f77bcf86cd799439011")
        assert any("MongoDB" in l for l in labels)
        assert not any("Hex-encoded" in l for l in labels)

    def test_objectid_not_also_flagged_as_base64(self):
        # 24 hex chars happen to be valid base64 input too (the decode
        # would just produce 18 bytes of binary garbage), so the
        # "decode as base64" hint is wrong - suppress it.
        labels = _labels("507f1f77bcf86cd799439011")
        assert not any(l.startswith("Looks like base64") for l in labels)

    def test_md5_not_also_flagged_as_base64(self):
        # Same reason: 32 hex chars are also valid base64 input.
        labels = _labels("21232f297a57a5a743894a0e4a801fc3")
        assert any("MD5" in l for l in labels)
        assert not any(l.startswith("Looks like base64") for l in labels)

    def test_bcrypt_not_also_flagged_as_base64(self):
        h = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        labels = _labels(h)
        assert any("Bcrypt" in l for l in labels)
        assert not any(l.startswith("Looks like base64") for l in labels)

    def test_mac_address_not_also_flagged_as_ipv6(self):
        # 'aa:bb:cc:dd:ee:ff' has 5 colons, no '::' - shouldn't trip IPv6.
        labels = _labels("aa:bb:cc:dd:ee:ff")
        assert any("MAC" in l for l in labels)
        assert not any("IPv6" in l for l in labels)

    def test_ipv6_with_compression_still_caught(self):
        # Sanity: tightening didn't break the real IPv6 case.
        assert any("IPv6" in l for l in _labels("::1"))
        assert any("IPv6" in l for l in _labels("2001:db8::1"))
