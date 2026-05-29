"""
Tests for intruder.py.

Covers the pure-logic pieces: RawRequest parsing/substitution, the
four attack-mode generators, range-spec parsing, and the matcher.
Network code (build_session, send, fuzz) isn't tested here because
it would need a live HTTP target; integration tests against a real
PortSwigger lab are out of scope for unit tests.
"""
import re

import pytest

from intruder import (
    MARKER_RE, RawRequest, parse_range_spec, range_matches, Matcher,
    parse_jitter, sniper, battering_ram, pitchfork, cluster_bomb,
    apply_encoding, parse_encode_chain, ENCODERS,
    write_json, write_csv, write_html, write_markdown,
)


# ---------------------------------------------------------------------
# MARKER_RE
# ---------------------------------------------------------------------
class TestMarkerRegex:
    def test_matches_single_marker(self):
        assert MARKER_RE.findall("hello §FUZZ§ world") == ["FUZZ"]

    def test_matches_multiple(self):
        assert MARKER_RE.findall("§A§§B§§C§") == ["A", "B", "C"]

    def test_matches_empty_marker(self):
        assert MARKER_RE.findall("§§") == [""]

    def test_no_match_with_only_one_section_sign(self):
        assert MARKER_RE.findall("hello § world") == []


# ---------------------------------------------------------------------
# RawRequest parsing
# ---------------------------------------------------------------------
class TestRawRequestParse:
    def test_parses_method_and_path(self):
        r = RawRequest.parse("GET /admin HTTP/1.1\r\nHost: x.com\r\n\r\n")
        assert r.method == "GET"
        assert r.path == "/admin"

    def test_parses_headers_in_order(self):
        r = RawRequest.parse("GET / HTTP/1.1\r\nHost: x\r\nFoo: bar\r\n\r\n")
        assert r.headers == [("Host", "x"), ("Foo", "bar")]

    def test_parses_body(self):
        r = RawRequest.parse("POST /a HTTP/1.1\r\nHost: x\r\n\r\nhello world")
        assert r.body == "hello world"

    def test_handles_lf_only_input(self):
        # Users paste with \n from text editors; we normalize to \r\n.
        r = RawRequest.parse("GET / HTTP/1.1\nHost: x\nFoo: bar\n\nbody")
        assert r.body == "body"
        assert r.headers == [("Host", "x"), ("Foo", "bar")]

    def test_empty_body_when_no_body(self):
        r = RawRequest.parse("GET / HTTP/1.1\r\nHost: x\r\n")
        assert r.body == ""

    def test_host_extracts_from_headers(self):
        r = RawRequest.parse("GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
        assert r.host() == "target.com"

    def test_host_is_case_insensitive(self):
        r = RawRequest.parse("GET / HTTP/1.1\r\nhost: lower.com\r\n\r\n")
        assert r.host() == "lower.com"

    def test_host_returns_none_when_absent(self):
        r = RawRequest.parse("GET / HTTP/1.1\r\nFoo: bar\r\n\r\n")
        assert r.host() is None

    def test_strips_preamble_comments(self):
        # Comments before the request line should be ignored so
        # example templates can be self-documenting.
        text = (
            "# This is a comment explaining the template\n"
            "# Edit the Host header below\n"
            "POST /login HTTP/1.1\nHost: x\n\nbody"
        )
        r = RawRequest.parse(text)
        assert r.method == "POST"
        assert r.path == "/login"
        assert r.host() == "x"
        assert r.body == "body"

    def test_strips_interspersed_comments(self):
        text = (
            "GET / HTTP/1.1\n"
            "# header comment\n"
            "Host: x.com\n"
            "# another\n"
            "Foo: bar\n\n"
        )
        r = RawRequest.parse(text)
        assert r.headers == [("Host", "x.com"), ("Foo", "bar")]

    def test_does_not_strip_hash_in_body(self):
        # `#` inside a body line (e.g. as part of form data or JSON)
        # must NOT be stripped.
        text = "POST / HTTP/1.1\nHost: x\n\n#tag=foo&other=bar"
        r = RawRequest.parse(text)
        assert r.body == "#tag=foo&other=bar"


# ---------------------------------------------------------------------
# RawRequest substitution
# ---------------------------------------------------------------------
class TestRawRequestSubstitution:
    def _req(self):
        return RawRequest.parse(
            "POST /a HTTP/1.1\r\nHost: x\r\n\r\nuser=§U§&pw=§P§"
        )

    def test_marker_count(self):
        assert self._req().marker_count() == 2

    def test_substitutes_both_markers(self):
        sub = self._req().substituted(["alice", "secret"])
        assert sub.body == "user=alice&pw=secret"

    def test_falls_back_to_literal_on_none(self):
        # None at position 1 should leave the marker as literal text
        # (the text between the §§, without the § symbols).
        sub = self._req().substituted(["alice", None])
        assert sub.body == "user=alice&pw=P"

    def test_substitutes_in_path(self):
        r = RawRequest.parse("GET /admin/§F§ HTTP/1.1\r\nHost: x\r\n\r\n")
        sub = r.substituted(["secret"])
        assert sub.path == "/admin/secret"

    def test_substitutes_in_header_value(self):
        r = RawRequest.parse("GET / HTTP/1.1\r\nX-Forwarded-For: §IP§\r\n\r\n")
        sub = r.substituted(["1.2.3.4"])
        assert sub.headers == [("X-Forwarded-For", "1.2.3.4")]


# ---------------------------------------------------------------------
# parse_range_spec + range_matches
# ---------------------------------------------------------------------
class TestRangeSpec:
    @pytest.mark.parametrize("spec,expected", [
        ("404",      (404.0, 404.0, False)),
        ("200-299",  (200.0, 299.0, False)),
        ("5000-",    (5000.0, float("inf"), False)),
        ("-1000",    (0.0, 1000.0, False)),
        ("!403",     (403.0, 403.0, True)),
        ("!200-299", (200.0, 299.0, True)),
    ])
    def test_parsing(self, spec, expected):
        assert parse_range_spec(spec) == expected

    def test_matches_single_value(self):
        spec = parse_range_spec("404")
        assert range_matches(spec, 404)
        assert not range_matches(spec, 200)

    def test_matches_range(self):
        spec = parse_range_spec("200-299")
        assert range_matches(spec, 200)
        assert range_matches(spec, 250)
        assert range_matches(spec, 299)
        assert not range_matches(spec, 199)
        assert not range_matches(spec, 300)

    def test_matches_negation(self):
        spec = parse_range_spec("!403")
        assert range_matches(spec, 200)
        assert range_matches(spec, 500)
        assert not range_matches(spec, 403)

    def test_matches_open_upper(self):
        spec = parse_range_spec("5000-")
        assert range_matches(spec, 5000)
        assert range_matches(spec, 1000000)
        assert not range_matches(spec, 4999)

    def test_none_spec_always_matches(self):
        assert range_matches(None, 0)
        assert range_matches(None, 99999)


# ---------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------
class TestMatcher:
    def test_no_rules_always_matches(self):
        m = Matcher()
        assert m.matches(200, 1000, "anything", 0.5)
        assert not m.any_enabled()

    def test_status_filter(self):
        m = Matcher(status=parse_range_spec("200-299"))
        assert m.matches(200, 0, "", 0)
        assert not m.matches(404, 0, "", 0)

    def test_length_filter(self):
        m = Matcher(length=parse_range_spec("!3168"))
        assert m.matches(200, 5000, "", 0)
        assert not m.matches(200, 3168, "", 0)

    def test_and_logic(self):
        m = Matcher(status=parse_range_spec("200"),
                    length=parse_range_spec("100-200"))
        assert m.matches(200, 150, "", 0)
        assert not m.matches(200, 300, "", 0)         # length fails
        assert not m.matches(404, 150, "", 0)         # status fails

    def test_regex_positive(self):
        m = Matcher(regex=re.compile("admin"))
        assert m.matches(200, 0, "hello admin user", 0)
        assert not m.matches(200, 0, "guest user", 0)

    def test_regex_negative(self):
        m = Matcher(regex=re.compile("forbidden"), regex_negate=True)
        assert m.matches(200, 0, "welcome user", 0)
        assert not m.matches(200, 0, "forbidden access", 0)


# ---------------------------------------------------------------------
# Attack-mode generators
# ---------------------------------------------------------------------
@pytest.fixture
def two_marker_req():
    return RawRequest.parse(
        "POST /a HTTP/1.1\r\nHost: x\r\n\r\nu=§U§&p=§P§"
    )


class TestSniper:
    def test_request_count(self, two_marker_req):
        # 2 markers x 3 payloads = 6 requests
        results = list(sniper(two_marker_req, ["a", "b", "c"]))
        assert len(results) == 6

    def test_one_marker_at_a_time(self, two_marker_req):
        # Iteration 0 (pos=0, value="a") -> "u=a&p=P" (P is literal fallback)
        results = list(sniper(two_marker_req, ["a"]))
        assert results[0][1].body == "u=a&p=P"   # pos 0 substituted
        results = list(sniper(two_marker_req, ["b"]))
        # With one payload, pos=1 iteration gives "u=U&p=b"
        # (sniper iterates pos 0 first, then pos 1)
        bodies = [sub.body for label, sub in sniper(two_marker_req, ["x"])]
        assert "u=x&p=P" in bodies
        assert "u=U&p=x" in bodies


class TestBatteringRam:
    def test_substitutes_everywhere(self, two_marker_req):
        results = list(battering_ram(two_marker_req, ["xx"]))
        assert len(results) == 1
        assert results[0][1].body == "u=xx&p=xx"

    def test_one_request_per_payload(self, two_marker_req):
        results = list(battering_ram(two_marker_req, ["a", "b", "c"]))
        assert len(results) == 3


class TestPitchfork:
    def test_parallel_iteration(self, two_marker_req):
        results = list(pitchfork(two_marker_req, [["u1", "u2"], ["p1", "p2"]]))
        assert len(results) == 2
        assert results[0][1].body == "u=u1&p=p1"
        assert results[1][1].body == "u=u2&p=p2"

    def test_truncates_to_shortest(self, two_marker_req):
        # Lists of length 3 and 2 -> 2 iterations
        results = list(pitchfork(two_marker_req, [["a", "b", "c"], ["x", "y"]]))
        assert len(results) == 2


class TestClusterBomb:
    def test_cartesian_product(self, two_marker_req):
        results = list(cluster_bomb(two_marker_req, [["u1", "u2"], ["p1", "p2"]]))
        assert len(results) == 4
        bodies = sorted(sub.body for _, sub in results)
        assert bodies == ["u=u1&p=p1", "u=u1&p=p2", "u=u2&p=p1", "u=u2&p=p2"]


# ---------------------------------------------------------------------
# parse_jitter
# ---------------------------------------------------------------------
class TestJitter:
    @pytest.mark.parametrize("s,expected", [
        ("0",       (0.0, 0.0)),
        ("0.5",     (0.5, 0.5)),
        ("0.5-2.0", (0.5, 2.0)),
        ("1-3",     (1.0, 3.0)),
    ])
    def test_parse(self, s, expected):
        assert parse_jitter(s) == expected


# ---------------------------------------------------------------------
# Payload encoders (--encode)
# ---------------------------------------------------------------------
class TestEncoders:
    def test_none_is_identity(self):
        assert ENCODERS["none"]("abc") == "abc"

    def test_url_encodes_special_chars(self):
        # Single quote, space, equals, ampersand - all common in SQLi
        # payloads, all must be percent-encoded with safe="".
        assert ENCODERS["url"]("' OR 1=1") == "%27%20OR%201%3D1"
        # `/` is in `safe=""` for our encoder (we override the default).
        assert ENCODERS["url"]("a/b") == "a%2Fb"

    def test_double_url(self):
        # Double-URL: each %XX itself becomes %25XX.
        assert ENCODERS["double-url"]("'") == "%2527"

    def test_base64(self):
        assert ENCODERS["base64"]("admin") == "YWRtaW4="

    def test_hex(self):
        assert ENCODERS["hex"]("OR") == "4f52"

    def test_html(self):
        assert ENCODERS["html"]("<script>") == "&lt;script&gt;"


class TestApplyEncoding:
    def test_empty_chain_is_identity(self):
        assert apply_encoding("hello", []) == "hello"

    def test_chain_applies_in_order(self):
        # url first: '/' -> '%2F'. Then base64 the result.
        once = ENCODERS["url"]("a/b")
        twice = ENCODERS["base64"](once)
        assert apply_encoding("a/b", ["url", "base64"]) == twice

    def test_chain_reversed_gives_different_result(self):
        # base64 first, then url - very different from url then base64.
        forward  = apply_encoding("a/b", ["url", "base64"])
        reverse  = apply_encoding("a/b", ["base64", "url"])
        assert forward != reverse


class TestParseEncodeChain:
    def test_empty_returns_empty_list(self):
        assert parse_encode_chain("") == []

    def test_none_returns_empty_list(self):
        assert parse_encode_chain("none") == []

    def test_single(self):
        assert parse_encode_chain("url") == ["url"]

    def test_comma_separated(self):
        assert parse_encode_chain("url,base64") == ["url", "base64"]

    def test_whitespace_tolerated(self):
        assert parse_encode_chain("url , base64") == ["url", "base64"]

    def test_unknown_encoder_exits(self):
        with pytest.raises(SystemExit):
            parse_encode_chain("rot13")


# ---------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------
@pytest.fixture
def sample_results():
    return [
        {"label": "sniper pos=0 value='admin'", "status": 200, "length": 3170,
         "time": 0.18, "hit": True,  "error": None},
        {"label": "sniper pos=0 value='guest'", "status": 200, "length": 3168,
         "time": 0.12, "hit": False, "error": None},
        {"label": "sniper pos=0 value='broken'", "status": None, "length": 0,
         "time": 0.00, "hit": False, "error": "connection refused"},
    ]


class TestWriteJson:
    def test_writes_valid_json(self, sample_results, tmp_path):
        import json as json_mod
        out = tmp_path / "out.json"
        write_json(sample_results, out)
        loaded = json_mod.loads(out.read_text())
        assert loaded == sample_results


class TestWriteCsv:
    def test_writes_csv_with_header(self, sample_results, tmp_path):
        import csv as csv_mod
        out = tmp_path / "out.csv"
        write_csv(sample_results, out)
        rows = list(csv_mod.DictReader(out.open()))
        assert len(rows) == 3
        # CSV stringifies everything; check the values came through.
        assert rows[0]["label"] == "sniper pos=0 value='admin'"
        assert rows[0]["status"] == "200"
        assert rows[0]["hit"] == "True"
        # And errors landed in the right column for the failing row.
        assert rows[2]["error"] == "connection refused"


class TestWriteMarkdown:
    def test_includes_summary_and_table(self, sample_results, tmp_path):
        out = tmp_path / "out.md"
        write_markdown(sample_results, out)
        text = out.read_text()
        # Summary numbers
        assert "Total requests:** 3" in text
        assert "Hits:** 1" in text
        assert "Errors:** 1" in text
        # Header row
        assert "| Label | Status | Length |" in text
        # Hit checkmark
        assert "✓" in text
        # The error message is in the table
        assert "connection refused" in text

    def test_escapes_pipe_in_label(self, tmp_path):
        results = [{"label": "weird|label", "status": 200, "length": 0,
                    "time": 0.0, "hit": True, "error": None}]
        out = tmp_path / "x.md"
        write_markdown(results, out)
        assert r"weird\|label" in out.read_text()


class TestWriteHtml:
    def test_writes_full_html_doc(self, sample_results, tmp_path):
        out = tmp_path / "out.html"
        write_html(sample_results, out)
        text = out.read_text()
        assert "<!DOCTYPE html>" in text
        assert "<title>Intruder results</title>" in text
        # Summary
        assert "Total: <b>3</b>" in text
        assert "Hits: <b>1</b>" in text
        # Hit row gets the .hit class for green highlighting
        assert 'class="hit"' in text

    def test_escapes_xss_in_label(self, tmp_path):
        # CRITICAL: labels can contain payload strings including XSS.
        # Writing them unescaped into HTML would actively execute the
        # XSS payload when the report is opened. html.escape must
        # neutralize <, >, ", ', &.
        results = [{"label": "<script>alert(1)</script>",
                    "status": 200, "length": 0, "time": 0.0,
                    "hit": True, "error": None}]
        out = tmp_path / "x.html"
        write_html(results, out)
        text = out.read_text()
        # The literal script tag must NOT appear.
        assert "<script>alert(1)</script>" not in text
        # The escaped form must appear instead.
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
