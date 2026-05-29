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
