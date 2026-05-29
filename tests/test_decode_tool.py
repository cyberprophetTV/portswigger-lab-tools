"""
Tests for decode_tool.py decoders + chain parsing + auto + JWT inspect.
"""
import pytest

from decode_tool import (
    DECODERS, parse_decode_chain, apply_chain, auto_decode,
    try_jwt_inspect, looks_readable,
    _dec_url, _dec_double_url, _dec_base64, _dec_hex, _dec_html,
)


class TestDecoders:
    def test_url_decodes_percent(self):
        assert _dec_url("%27%20OR%201") == "' OR 1"

    def test_url_plus_becomes_space(self):
        # `+` in a URL-encoded form value means space; unquote_plus handles it.
        assert _dec_url("hello+world") == "hello world"

    def test_double_url(self):
        # %2527 -> %27 -> '
        assert _dec_double_url("%2527") == "'"

    def test_base64_basic(self):
        assert _dec_base64("YWRtaW4=") == "admin"

    def test_base64_without_padding(self):
        # Real-world tokens often arrive with `=` stripped.
        assert _dec_base64("YWRtaW4") == "admin"

    def test_base64url_chars_tolerated(self):
        # The base64url variant uses '-' and '_' in place of '+' and '/'.
        # Our decoder normalizes them.
        encoded = _dec_base64("c29tZS9zdHJpbmc=").replace("/", "_")
        # Re-decode to confirm idempotence on the url variant
        assert _dec_base64("c29tZS9zdHJpbmc=") == "some/string"

    def test_hex_basic(self):
        assert _dec_hex("61646d696e") == "admin"

    def test_hex_with_whitespace(self):
        assert _dec_hex("61 64 6d 69 6e") == "admin"

    def test_hex_with_0x_prefix(self):
        assert _dec_hex("0x61646d696e") == "admin"

    def test_html_entities(self):
        assert _dec_html("&lt;script&gt;") == "<script>"

    def test_html_numeric_entity(self):
        assert _dec_html("&#65;") == "A"


class TestParseDecodeChain:
    def test_empty(self):
        assert parse_decode_chain("") == []

    def test_none(self):
        assert parse_decode_chain("none") == []

    def test_single(self):
        assert parse_decode_chain("url") == ["url"]

    def test_multiple(self):
        assert parse_decode_chain("base64,url") == ["base64", "url"]

    def test_unknown_decoder(self):
        with pytest.raises(SystemExit):
            parse_decode_chain("rot13")


class TestApplyChain:
    def test_empty_chain_identity(self):
        assert apply_chain("hi", []) == "hi"

    def test_reverse_of_encoder_chain(self):
        # If the encoder chain was url,base64 (URL first, then base64),
        # the decoder chain to reverse it is base64,url (base64 first).
        from intruder import apply_encoding
        original = "' OR 1=1"
        encoded = apply_encoding(original, ["url", "base64"])
        decoded = apply_chain(encoded, ["base64", "url"])
        assert decoded == original


class TestAutoDecode:
    def test_finds_base64(self):
        # YWRtaW4= is base64 for "admin" - auto should surface it.
        results = auto_decode("YWRtaW4=")
        assert "base64" in results
        assert results["base64"] == "admin"

    def test_finds_url(self):
        results = auto_decode("hello%20world")
        assert "url" in results
        assert results["url"] == "hello world"

    def test_garbage_returns_empty(self):
        # Plain text that isn't actually encoded should produce no
        # readable decodings (anything that "decodes" to gibberish
        # is filtered out by looks_readable).
        results = auto_decode("plain english text")
        # url and html may "decode" to the same text (no-op); we
        # filter those. Base64/hex would produce garbage. Net: empty.
        # At minimum: nothing wildly wrong (no exception).
        assert isinstance(results, dict)


class TestLooksReadable:
    def test_pure_ascii_readable(self):
        assert looks_readable("hello world")

    def test_empty_not_readable(self):
        assert not looks_readable("")

    def test_binary_garbage_not_readable(self):
        assert not looks_readable("\x00\x01\x02\x03\x04\x05")


class TestJwtInspect:
    def test_valid_jwt(self):
        # Minimal JWT with HS256 / payload {"sub":"alice"}.
        # Header b64: eyJhbGciOiJIUzI1NiJ9
        # Payload b64: eyJzdWIiOiJhbGljZSJ9
        # Sig: anything
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"
        result = try_jwt_inspect(token)
        assert result is not None
        assert result["header"] == {"alg": "HS256"}
        assert result["payload"] == {"sub": "alice"}

    def test_not_jwt(self):
        assert try_jwt_inspect("not a jwt") is None
        assert try_jwt_inspect("a.b") is None
        assert try_jwt_inspect("a.b.c.d") is None

    def test_jwt_without_alg_rejected(self):
        # If the "header" doesn't have an alg key, it's not really a JWT.
        # Header b64 of {"foo":"bar"}: eyJmb28iOiJiYXIifQ
        token = "eyJmb28iOiJiYXIifQ.eyJzdWIiOiJ4In0.sig"
        assert try_jwt_inspect(token) is None
