"""
Tests for workflow.py - variable substitution + extractors.
Network-touching code (run_step, run_fuzz) requires a fixture
server; tested manually.
"""
import json
from unittest.mock import MagicMock

import pytest

from workflow import (
    substitute_str, substitute_deep, find_unresolved,
    extract_value, parse_var,
)


# ---------------------------------------------------------------------
# substitute_str
# ---------------------------------------------------------------------
class TestSubstituteStr:
    def test_replaces_known_var(self):
        assert substitute_str("hello {{name}}", {"name": "world"}) == "hello world"

    def test_leaves_unknown_var(self):
        # Unknown vars stay as the literal {{var}} so we can find
        # them later (and the user can see what didn't resolve).
        assert substitute_str("hello {{name}}", {}) == "hello {{name}}"

    def test_multiple_substitutions(self):
        out = substitute_str("{{a}}/{{b}}/{{a}}", {"a": "X", "b": "Y"})
        assert out == "X/Y/X"

    def test_handles_non_string(self):
        # Pass-through for non-strings - useful when calling on dict values.
        assert substitute_str(42, {"a": "x"}) == 42
        assert substitute_str(None, {"a": "x"}) is None

    def test_alphanumeric_var_names(self):
        assert substitute_str("{{foo_bar_123}}", {"foo_bar_123": "ok"}) == "ok"

    def test_var_with_space_not_matched(self):
        # {{my var}} isn't a valid var name (no spaces), left alone.
        assert substitute_str("{{my var}}", {"my var": "x"}) == "{{my var}}"


# ---------------------------------------------------------------------
# substitute_deep
# ---------------------------------------------------------------------
class TestSubstituteDeep:
    def test_substitutes_in_nested_dict(self):
        obj = {"url": "{{base}}/path", "headers": {"X-Token": "{{token}}"}}
        out = substitute_deep(obj, {"base": "https://x", "token": "abc"})
        assert out["url"] == "https://x/path"
        assert out["headers"]["X-Token"] == "abc"

    def test_substitutes_in_list(self):
        out = substitute_deep(["{{a}}", "{{b}}"], {"a": "1", "b": "2"})
        assert out == ["1", "2"]

    def test_preserves_non_strings(self):
        out = substitute_deep({"workers": 5, "url": "{{u}}"}, {"u": "x"})
        assert out == {"workers": 5, "url": "x"}


# ---------------------------------------------------------------------
# find_unresolved
# ---------------------------------------------------------------------
class TestFindUnresolved:
    def test_finds_unresolved_in_string(self):
        assert find_unresolved("{{a}} {{b}}") == ["a", "b"]

    def test_no_markers(self):
        assert find_unresolved("plain text") == []

    def test_recurses_into_nested(self):
        obj = {"a": "x{{foo}}", "b": ["{{bar}}"]}
        found = find_unresolved(obj)
        assert "foo" in found
        assert "bar" in found


# ---------------------------------------------------------------------
# extract_value
# ---------------------------------------------------------------------
class TestExtractValue:
    def _resp(self, *, text="", cookies=None, headers=None, json_data=None):
        """Build a minimal mock response."""
        r = MagicMock()
        r.text = text
        r.cookies = cookies or {}
        # MagicMock's headers behavior is awkward; use a real dict.
        r.headers = {} if headers is None else headers
        if json_data is not None:
            r.json = MagicMock(return_value=json_data)
        else:
            r.json = MagicMock(side_effect=ValueError("not JSON"))
        return r

    def test_regex_capture_group(self):
        r = self._resp(text='<input name="csrf" value="ABC123">')
        out = extract_value({"regex": r'name="csrf" value="([^"]+)"'}, r)
        assert out == "ABC123"

    def test_regex_no_capture_group(self):
        # When the pattern has no capture group, return the whole match.
        r = self._resp(text="hello there")
        out = extract_value({"regex": r"hello"}, r)
        assert out == "hello"

    def test_regex_no_match_returns_none(self):
        r = self._resp(text="nothing matches")
        assert extract_value({"regex": "foo"}, r) is None

    def test_cookie_lookup(self):
        # requests.cookies is a CookieJar but supports .get(name)
        cookies = MagicMock()
        cookies.get = MagicMock(return_value="session-abc")
        r = self._resp(cookies=cookies)
        assert extract_value({"cookie": "session"}, r) == "session-abc"

    def test_header_lookup(self):
        r = self._resp(headers={"X-CSRF-Token": "xyz"})
        assert extract_value({"header": "X-CSRF-Token"}, r) == "xyz"

    def test_jsonpath_basic(self):
        r = self._resp(json_data={"user": {"name": "alice"}})
        assert extract_value({"jsonpath": "$.user.name"}, r) == "alice"

    def test_jsonpath_missing_returns_none(self):
        r = self._resp(json_data={"user": {}})
        assert extract_value({"jsonpath": "$.user.name"}, r) is None

    def test_jsonpath_non_json_returns_none(self):
        r = self._resp(text="not json")   # json() raises
        assert extract_value({"jsonpath": "$.x"}, r) is None

    def test_invalid_extractor_raises(self):
        r = self._resp()
        with pytest.raises(ValueError):
            extract_value({"unknown_kind": "x"}, r)

    def test_empty_extractor_raises(self):
        r = self._resp()
        with pytest.raises(ValueError):
            extract_value({}, r)


# ---------------------------------------------------------------------
# parse_var
# ---------------------------------------------------------------------
class TestParseVar:
    def test_basic(self):
        assert parse_var("name=value") == ("name", "value")

    def test_value_with_equals(self):
        assert parse_var("token=abc=def") == ("token", "abc=def")

    def test_missing_equals_exits(self):
        with pytest.raises(SystemExit):
            parse_var("just_name")
