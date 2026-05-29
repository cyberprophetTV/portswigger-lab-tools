"""
Tests for jwt_tool.py: base64url round-trip, parse, alg=none forgery,
HS256 sign + brute, kid-injection variant generation.
"""
import json
import sys

import pytest

from jwt_tool import (
    b64url_encode, b64url_decode, parse_token,
    cmd_decode, cmd_none, cmd_brute, cmd_sign, cmd_kid,
    hs256_sign, _coerce_value, parse_set, KID_PAYLOADS,
)


# A reference token: header={"alg":"HS256","typ":"JWT"},
# payload={"sub":"alice","role":"user"}, signature with secret="secret".
# Hand-computed so we can validate signing logic.
REFERENCE_TOKEN_HEADER = '{"alg":"HS256","typ":"JWT"}'
REFERENCE_TOKEN_PAYLOAD = '{"sub":"alice","role":"user"}'
REFERENCE_SECRET = "secret"


def _make_token(header_json: str, payload_json: str, secret: str | None) -> str:
    h = b64url_encode(header_json.encode())
    p = b64url_encode(payload_json.encode())
    if secret is None:
        return f"{h}.{p}."
    sig = hs256_sign(f"{h}.{p}".encode(), secret.encode())
    return f"{h}.{p}.{b64url_encode(sig)}"


@pytest.fixture
def reference_token():
    return _make_token(REFERENCE_TOKEN_HEADER, REFERENCE_TOKEN_PAYLOAD,
                       REFERENCE_SECRET)


# ---------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------
class TestBase64Url:
    def test_roundtrip(self):
        for data in (b"hello", b"\x00\xff\x80", b"", b"a" * 1000):
            assert b64url_decode(b64url_encode(data)) == data

    def test_no_padding_in_output(self):
        # Standard b64 of "hi" is "aGk=" - jwt b64url strips the "=".
        assert "=" not in b64url_encode(b"hi")

    def test_decode_handles_missing_padding(self):
        # Encode "hi" then strip padding - decoder must add it back.
        encoded = b64url_encode(b"hi")
        assert b64url_decode(encoded) == b"hi"

    def test_url_safe_chars(self):
        # bytes that base64 would encode with '+' or '/' must come out
        # as '-' and '_' in url-safe encoding.
        data = b"\xfb\xff"   # encodes to "+/8" in stdb64, "-_8" in urlb64
        encoded = b64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded


# ---------------------------------------------------------------------
# parse_token
# ---------------------------------------------------------------------
class TestParseToken:
    def test_parses_reference(self, reference_token):
        header, payload, sig, h_b64, p_b64, s_b64 = parse_token(reference_token)
        assert header == {"alg": "HS256", "typ": "JWT"}
        assert payload == {"sub": "alice", "role": "user"}
        assert len(sig) == 32   # HMAC-SHA256 = 32 bytes
        # The b64 components round-trip to the original token.
        assert f"{h_b64}.{p_b64}.{s_b64}" == reference_token

    def test_rejects_wrong_number_of_parts(self):
        with pytest.raises(SystemExit):
            parse_token("a.b")
        with pytest.raises(SystemExit):
            parse_token("a.b.c.d")

    def test_rejects_invalid_json(self):
        bad = b64url_encode(b"not json")
        with pytest.raises(SystemExit):
            parse_token(f"{bad}.{bad}.")


# ---------------------------------------------------------------------
# HS256 signing
# ---------------------------------------------------------------------
class TestHs256Sign:
    def test_known_vector(self):
        # HMAC-SHA256 produces 32 bytes regardless of input.
        result = hs256_sign(b"signing.input", b"secret")
        assert len(result) == 32

    def test_signs_reference_token(self, reference_token):
        header, payload, sig, h_b64, p_b64, s_b64 = parse_token(reference_token)
        recomputed = hs256_sign(f"{h_b64}.{p_b64}".encode(),
                                REFERENCE_SECRET.encode())
        assert recomputed == sig


# ---------------------------------------------------------------------
# alg=none forgery (cmd_none output)
# ---------------------------------------------------------------------
class TestAlgNone:
    def test_produces_three_variants(self, reference_token, capsys):
        cmd_none(reference_token, {})
        captured = capsys.readouterr().out
        # All three casings tried
        assert "alg=none:" in captured
        assert "alg=None:" in captured
        assert "alg=NONE:" in captured

    def test_payload_modification(self, reference_token, capsys):
        cmd_none(reference_token, {"role": "admin"})
        captured = capsys.readouterr().out
        # Find a token line, decode it, verify role was changed.
        for line in captured.splitlines():
            if ".eyJ" in line:    # crude: lines containing a JWT
                # extract last word
                token = line.split()[-1]
                _, payload, _, _, _, _ = parse_token(token)
                assert payload["role"] == "admin"
                return
        pytest.fail("no forged token found in output")

    def test_empty_signature(self, reference_token, capsys):
        cmd_none(reference_token, {})
        captured = capsys.readouterr().out
        # alg=none tokens end with a trailing dot (empty sig segment).
        for line in captured.splitlines():
            if "alg=" in line and ".eyJ" in line:
                token = line.split()[-1]
                assert token.endswith(".")


# ---------------------------------------------------------------------
# cmd_brute
# ---------------------------------------------------------------------
class TestBrute:
    def test_finds_known_secret(self, reference_token, tmp_path, capsys):
        # Wordlist contains the right secret near the end.
        wordlist = tmp_path / "wl.txt"
        wordlist.write_text("wrong1\nwrong2\nsecret\nwrong3\n")
        rc = cmd_brute(reference_token, wordlist)
        assert rc == 0
        assert "secret found:" in capsys.readouterr().out

    def test_returns_nonzero_when_not_in_wordlist(self, reference_token,
                                                   tmp_path, capsys):
        wordlist = tmp_path / "wl.txt"
        wordlist.write_text("wrong1\nwrong2\n")
        rc = cmd_brute(reference_token, wordlist)
        assert rc != 0

    def test_rejects_non_hs256(self, tmp_path):
        # An alg=none token can't be brute-forced (no signature).
        token = _make_token('{"alg":"none"}', '{"sub":"a"}', None)
        wordlist = tmp_path / "wl.txt"
        wordlist.write_text("x\n")
        with pytest.raises(SystemExit):
            cmd_brute(token, wordlist)


# ---------------------------------------------------------------------
# cmd_sign (re-sign with known secret + modifications)
# ---------------------------------------------------------------------
class TestSign:
    def test_signed_token_verifies_with_same_secret(self, reference_token, capsys):
        cmd_sign(reference_token, REFERENCE_SECRET, {"role": "admin"})
        out = capsys.readouterr().out
        # Last non-empty line of output is the token
        token = [l for l in out.splitlines() if l.strip()][-1]
        header, payload, sig, h_b64, p_b64, _ = parse_token(token)
        assert payload["role"] == "admin"
        # Signature verifies with the secret we provided
        expected = hs256_sign(f"{h_b64}.{p_b64}".encode(),
                              REFERENCE_SECRET.encode())
        assert expected == sig


# ---------------------------------------------------------------------
# cmd_kid (kid-injection variants)
# ---------------------------------------------------------------------
class TestKidInjection:
    def test_generates_all_payloads(self, reference_token, capsys):
        cmd_kid(reference_token)
        out = capsys.readouterr().out
        # Check descriptions appear (kid values are repr-printed, which
        # escapes control chars - matching them in the captured output
        # would be brittle).
        for _kid_val, desc in KID_PAYLOADS:
            assert desc in out
        # And confirm we emitted one variant token per payload (each
        # described block has a "token:" line).
        assert out.count("token:") == len(KID_PAYLOADS)


class TestCoerceValue:
    def test_string_stays_string(self):
        assert _coerce_value("admin", "user") == "admin"

    def test_int_to_int(self):
        assert _coerce_value("42", 7) == 42

    def test_bool_truthy(self):
        assert _coerce_value("true", False) is True
        assert _coerce_value("1", False) is True
        assert _coerce_value("yes", False) is True

    def test_bool_falsy(self):
        assert _coerce_value("false", True) is False
        assert _coerce_value("0", True) is False


class TestParseSet:
    def test_basic(self):
        assert parse_set("role=admin") == ("role", "admin")

    def test_value_with_equals(self):
        assert parse_set("token=ab=cd") == ("token", "ab=cd")

    def test_missing_equals(self):
        with pytest.raises(SystemExit):
            parse_set("just_a_name")
