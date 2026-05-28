"""
Tests for the pure-logic helpers in username_enum_solver.py.
Network-touching code (build_session, post_login, enumerate_username,
brute_password) is left to manual lab testing.
"""
import pytest

from username_enum_solver import (
    extract_error, CSRF_RE, ERROR_RE, parse_jitter,
)


class TestExtractError:
    def test_matches_portswigger_format(self):
        html = '<html><p class=is-warning>Invalid username</p></html>'
        assert extract_error(html) == "Invalid username"

    def test_matches_incorrect_password(self):
        html = '<p class=is-warning>Incorrect password</p>'
        assert extract_error(html) == "Incorrect password"

    def test_case_insensitive(self):
        html = '<P CLASS=IS-WARNING>Foo</P>'
        assert extract_error(html) == "Foo"

    def test_strips_whitespace(self):
        html = '<p class=is-warning>   spaced out   </p>'
        assert extract_error(html) == "spaced out"

    def test_returns_empty_when_no_match(self):
        assert extract_error("no warning class here") == ""

    def test_returns_empty_on_empty_input(self):
        assert extract_error("") == ""


class TestCsrfRegex:
    def test_quoted_attrs_name_first(self):
        html = '<input required type="hidden" name="csrf" value="ABC123">'
        m = CSRF_RE.search(html)
        assert m is not None
        # Either group 1 or group 2 has the value
        assert (m.group(1) or m.group(2)) == "ABC123"

    def test_quoted_attrs_value_first(self):
        html = '<input value="XYZ789" name="csrf" type="hidden">'
        m = CSRF_RE.search(html)
        assert m is not None
        assert (m.group(1) or m.group(2)) == "XYZ789"

    def test_no_match_when_no_csrf(self):
        html = '<input type="hidden" name="other" value="foo">'
        assert CSRF_RE.search(html) is None


class TestJitter:
    @pytest.mark.parametrize("s,expected", [
        ("0",       (0.0, 0.0)),
        ("0.5",     (0.5, 0.5)),
        ("0.5-2.0", (0.5, 2.0)),
    ])
    def test_parse(self, s, expected):
        assert parse_jitter(s) == expected
