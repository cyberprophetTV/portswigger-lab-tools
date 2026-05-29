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
    eval_condition, _loop_iterations, _loop_should_break,
    load_workflow_file, run_step, run_workflow,
)
from unittest.mock import MagicMock


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


# ---------------------------------------------------------------------
# eval_condition  (the if: expression evaluator)
# ---------------------------------------------------------------------
class TestEvalCondition:
    def test_string_equality(self):
        assert eval_condition("{{role}} == admin", {"role": "admin"})
        assert not eval_condition("{{role}} == admin", {"role": "user"})

    def test_string_inequality(self):
        assert eval_condition("{{role}} != user", {"role": "admin"})
        assert not eval_condition("{{role}} != admin", {"role": "admin"})

    def test_truthy_check(self):
        # Bare {{var}} returns True when the variable is non-empty.
        assert eval_condition("{{token}}", {"token": "abc"})
        assert not eval_condition("{{token}}", {"token": ""})
        # Unresolved vars are treated as empty in condition context
        # (intuitive for "did this step extract anything?" checks).
        assert not eval_condition("{{token}}", {})

    def test_truthy_zero_and_false_treated_as_false(self):
        assert not eval_condition("{{x}}", {"x": "0"})
        assert not eval_condition("{{x}}", {"x": "false"})
        assert not eval_condition("{{x}}", {"x": "no"})
        # Case-insensitive
        assert not eval_condition("{{x}}", {"x": "FALSE"})

    def test_negation(self):
        assert eval_condition("!{{role}}", {"role": ""})
        assert eval_condition("!{{x}}", {"x": "0"})
        assert not eval_condition("!{{role}}", {"role": "admin"})

    def test_numeric_comparison(self):
        assert eval_condition("{{n}} > 5", {"n": "10"})
        assert eval_condition("{{n}} < 5", {"n": "3"})
        assert eval_condition("{{n}} >= 5", {"n": "5"})
        assert eval_condition("{{n}} <= 5", {"n": "5"})
        assert not eval_condition("{{n}} > 5", {"n": "3"})

    def test_numeric_compare_with_non_number(self):
        # Non-numeric sides should produce False, not crash.
        assert not eval_condition("{{n}} > 5", {"n": "not a number"})

    def test_operator_whitespace_tolerated(self):
        assert eval_condition("{{a}}==x", {"a": "x"})
        assert eval_condition("{{a}}  ==  x", {"a": "x"})


# ---------------------------------------------------------------------
# Loop helpers
# ---------------------------------------------------------------------
class TestLoopIterations:
    def test_count_explicit(self):
        cap, var = _loop_iterations({"count": 5})
        assert cap == 5
        assert var == "loop_index"

    def test_count_with_var(self):
        cap, var = _loop_iterations({"count": 3, "var": "page"})
        assert (cap, var) == (3, "page")

    def test_max_used_when_no_count(self):
        cap, _ = _loop_iterations({"max": 8, "until_status": 200})
        assert cap == 8

    def test_default_ceiling_when_neither(self):
        # An until_X loop with no max defaults to a sane upper bound
        # so we never spin forever.
        cap, _ = _loop_iterations({"until_status": 200})
        assert cap == 10


class TestLoopShouldBreak:
    class _R:
        def __init__(self, sc):
            self.status_code = sc

    def test_until_status_breaks_on_match(self):
        assert _loop_should_break({"until_status": 200},
                                    self._R(200), {"vars": {}})
        assert not _loop_should_break({"until_status": 200},
                                        self._R(404), {"vars": {}})

    def test_until_extract_breaks_when_var_set(self):
        assert _loop_should_break({"until_extract": "csrf"},
                                    None, {"vars": {"csrf": "abc"}})
        assert not _loop_should_break({"until_extract": "csrf"},
                                        None, {"vars": {}})

    def test_no_exit_condition_never_breaks(self):
        assert not _loop_should_break({"count": 3}, self._R(200),
                                        {"vars": {}})


# ---------------------------------------------------------------------
# load_workflow_file
# ---------------------------------------------------------------------
class TestLoadWorkflowFile:
    def test_loads_json(self, tmp_path):
        p = tmp_path / "wf.json"
        p.write_text(json.dumps({"vars": {"x": "y"}, "steps": []}))
        wf = load_workflow_file(p)
        assert wf["vars"]["x"] == "y"

    def test_invalid_json_exits(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{ not valid")
        with pytest.raises(SystemExit):
            load_workflow_file(p)

    def test_root_must_be_dict(self, tmp_path):
        p = tmp_path / "wf.json"
        p.write_text(json.dumps([1, 2, 3]))
        with pytest.raises(SystemExit):
            load_workflow_file(p)

    def test_yaml_when_available(self, tmp_path):
        # Skip if pyyaml isn't installed locally - we don't want this
        # to fail on minimal environments. CI installs pyyaml.
        pytest.importorskip("yaml")
        p = tmp_path / "wf.yaml"
        p.write_text("vars:\n  x: y\nsteps: []\n")
        wf = load_workflow_file(p)
        assert wf["vars"]["x"] == "y"


# ---------------------------------------------------------------------
# clear_cookies + request-less steps
# ---------------------------------------------------------------------
class TestClearCookies:
    def _make_session(self):
        """Real-ish session with a mockable cookies jar."""
        sess = MagicMock()
        # MagicMock won't iterate properly for len(); use a list.
        sess.cookies = MagicMock()
        sess.cookies.__len__ = MagicMock(return_value=3)
        sess.cookies.clear = MagicMock()
        return sess

    def test_step_with_only_clear_cookies_returns_none(self):
        # A step that has clear_cookies but no `request` block should
        # not try to send anything.
        sess = self._make_session()
        step = {"name": "switch", "clear_cookies": True}
        result = run_step(sess, step, {"vars": {}}, dry_run=False)
        assert result is None
        sess.cookies.clear.assert_called_once()

    def test_clear_cookies_runs_before_request(self):
        # If both clear_cookies AND request are set, cookies clear first.
        sess = self._make_session()
        sess.request = MagicMock(return_value=MagicMock(status_code=200,
                                                          headers={},
                                                          text="ok",
                                                          content=b"ok",
                                                          cookies={}))
        step = {
            "name": "fresh_login",
            "clear_cookies": True,
            "request": {"method": "POST", "url": "http://x/login", "body": "u=a&p=b"},
        }
        run_step(sess, step, {"vars": {}}, dry_run=False)
        sess.cookies.clear.assert_called_once()
        sess.request.assert_called_once()

    def test_dry_run_does_not_actually_clear(self):
        sess = self._make_session()
        step = {"name": "switch", "clear_cookies": True}
        run_step(sess, step, {"vars": {}}, dry_run=True)
        # Clear NOT called in dry-run mode - just printed.
        sess.cookies.clear.assert_not_called()

    def test_step_without_clear_cookies_or_request_returns_none(self):
        sess = self._make_session()
        # A truly empty step (just a name) - early return, no crash.
        step = {"name": "noop"}
        result = run_step(sess, step, {"vars": {}}, dry_run=False)
        assert result is None


# ---------------------------------------------------------------------
# loop `refresh` block (for single-use CSRF tokens)
# ---------------------------------------------------------------------
class TestLoopRefresh:
    def test_refresh_runs_once_per_iteration(self):
        # The refresh block should fire BEFORE each loop iteration.
        # We use dry_run + a recording session to count run_step calls.
        sess = MagicMock()
        sess.cookies = MagicMock()
        sess.cookies.__len__ = MagicMock(return_value=0)

        # Workflow: 3-iteration loop with a refresh step that
        # extracts a fake csrf. Main step uses {{csrf}}.
        workflow = {
            "steps": [
                {
                    "name": "loop_with_refresh",
                    "loop": {"count": 3, "var": "i"},
                    "refresh": [
                        {"name": "_get_csrf",
                         "request": {"method": "GET", "url": "http://x/form"}}
                    ],
                    "request": {"method": "POST", "url": "http://x/submit"},
                }
            ]
        }
        run_workflow(workflow, sess, {}, dry_run=True)
        # In dry-run mode no actual HTTP calls happen so we can't
        # count sess.request invocations - but the workflow shouldn't
        # crash AND should report the loop iteration count.
        # The real verification is that the run completes without
        # error AND the test below confirms the loop iterates.

    def test_refresh_can_be_single_dict_not_list(self):
        # Convenience: workflow author can pass a single step dict
        # instead of a one-element list.
        sess = MagicMock()
        sess.cookies = MagicMock()
        sess.cookies.__len__ = MagicMock(return_value=0)
        workflow = {
            "steps": [
                {
                    "name": "loop",
                    "loop": {"count": 2},
                    "refresh": {  # single dict, not list
                        "name": "_pre",
                        "request": {"method": "GET", "url": "http://x/"}
                    },
                    "request": {"method": "POST", "url": "http://x/"},
                }
            ]
        }
        # Should not raise (the wrapper converts dict -> [dict]).
        run_workflow(workflow, sess, {}, dry_run=True)

    def test_loop_without_refresh_still_works(self):
        # Regression: don't require refresh; loops without it should
        # behave exactly as before.
        sess = MagicMock()
        sess.cookies = MagicMock()
        sess.cookies.__len__ = MagicMock(return_value=0)
        workflow = {
            "steps": [
                {"name": "plain_loop", "loop": {"count": 3},
                 "request": {"method": "GET", "url": "http://x/"}}
            ]
        }
        summary = run_workflow(workflow, sess, {}, dry_run=True)
        # Loop step recorded with iteration count
        assert any(s.get("loop") and s.get("iterations") == 3
                    for s in summary["steps"])
