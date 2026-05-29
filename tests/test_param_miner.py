"""
Tests for param_miner.py - injection helpers + body-format detection.
"""
import json

from param_miner import (
    inject_url_encoded, inject_json, detect_body_format,
    URL_TEST_VALUES, JSON_TEST_VALUES,
)


class TestInjectUrlEncoded:
    def test_appends_to_non_empty_body(self):
        assert inject_url_encoded("item=1", "admin", "true") == "item=1&admin=true"

    def test_handles_empty_body(self):
        assert inject_url_encoded("", "admin", "true") == "admin=true"

    def test_handles_whitespace_only_body(self):
        # A body of "   " counts as empty for injection purposes - we
        # don't want to produce "   &admin=true".
        assert inject_url_encoded("   ", "admin", "true") == "admin=true"

    def test_url_encodes_special_chars(self):
        # Spaces in the value must be percent-encoded so the resulting
        # body is a valid form-urlencoded string.
        assert inject_url_encoded("a=b", "role", "admin user") == \
            "a=b&role=admin%20user"

    def test_url_encodes_param_name(self):
        out = inject_url_encoded("a=b", "user role", "x")
        assert "user%20role=x" in out


class TestInjectJson:
    def test_adds_to_object(self):
        result = json.loads(inject_json('{"item":1}', "admin", True))
        assert result == {"item": 1, "admin": True}

    def test_string_value(self):
        result = json.loads(inject_json('{"item":1}', "role", "admin"))
        assert result == {"item": 1, "role": "admin"}

    def test_empty_body_becomes_object(self):
        result = json.loads(inject_json("", "admin", True))
        assert result == {"admin": True}

    def test_invalid_json_falls_back_to_object(self):
        # If the user pointed us at a non-JSON body but mislabeled it,
        # we still produce something usable instead of crashing.
        result = json.loads(inject_json("not json", "admin", True))
        assert result == {"admin": True}

    def test_array_body_returned_unchanged(self):
        # Adding a key to a JSON array doesn't make sense; we return
        # the original. Caller can decide what to do.
        original = '[1,2,3]'
        assert inject_json(original, "admin", True) == original

    def test_preserves_existing_keys(self):
        result = json.loads(inject_json('{"existing":"keep"}', "admin", True))
        assert "existing" in result
        assert result["admin"] is True


class TestDetectBodyFormat:
    def test_explicit_json_content_type(self):
        assert detect_body_format(
            [("Content-Type", "application/json")], '{}'
        ) == "json"

    def test_explicit_form_content_type(self):
        assert detect_body_format(
            [("Content-Type", "application/x-www-form-urlencoded")], 'a=b'
        ) == "form"

    def test_case_insensitive_header_name(self):
        assert detect_body_format(
            [("content-type", "application/json")], '{}'
        ) == "json"

    def test_sniffs_json_body_when_no_header(self):
        assert detect_body_format([], '{"a":1}') == "json"
        assert detect_body_format([], '[1,2,3]') == "json"

    def test_sniffs_form_body_when_no_header(self):
        assert detect_body_format([], 'a=b&c=d') == "form"

    def test_returns_none_for_unknown(self):
        assert detect_body_format([], 'plain text body') == "none"


class TestTestValues:
    def test_url_values_are_strings(self):
        # URL encoding is text-only - all test values must be strings.
        for v in URL_TEST_VALUES:
            assert isinstance(v, str)

    def test_json_values_cover_truthy_types(self):
        # JSON has distinct types - cover boolean, number, and string
        # so we catch servers that do strict type checking.
        types = {type(v) for v in JSON_TEST_VALUES}
        assert bool in types
        assert int in types
        assert str in types
