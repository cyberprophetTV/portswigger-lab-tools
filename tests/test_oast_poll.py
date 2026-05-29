"""
Tests for oast_poll.py — JSON/NDJSON loading + correlation logic.
"""
import json

import pytest

from oast_poll import (
    load_results, find_hits, correlate,
)


# ---------------------------------------------------------------------
# load_results
# ---------------------------------------------------------------------
class TestLoadResults:
    def test_loads_json_array(self, tmp_path):
        p = tmp_path / "r.json"
        data = [{"label": "x", "oob_id": "abc"}, {"label": "y"}]
        p.write_text(json.dumps(data))
        assert load_results(p) == data

    def test_loads_ndjson(self, tmp_path):
        p = tmp_path / "r.ndjson"
        lines = [
            json.dumps({"label": "a", "oob_id": "1"}),
            json.dumps({"label": "b", "oob_id": "2"}),
            "",   # blank lines should be skipped
            json.dumps({"label": "c"}),
        ]
        p.write_text("\n".join(lines))
        result = load_results(p)
        assert len(result) == 3
        assert result[0]["label"] == "a"

    def test_empty_file_exits(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("")
        with pytest.raises(SystemExit):
            load_results(p)

    def test_single_object_treated_as_ndjson_with_one_entry(self, tmp_path):
        # A file containing one JSON object is a valid NDJSON file
        # with a single entry - not an error.
        p = tmp_path / "r.json"
        p.write_text(json.dumps({"label": "single"}))
        result = load_results(p)
        assert len(result) == 1
        assert result[0]["label"] == "single"

    def test_json_array_of_non_objects_loads(self, tmp_path):
        # We accept whatever's in the JSON array; downstream code
        # decides what to do with weird entries.
        p = tmp_path / "r.json"
        p.write_text(json.dumps([1, 2, 3]))
        assert load_results(p) == [1, 2, 3]

    def test_invalid_json_array_exits(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text("[ not, valid")
        with pytest.raises(SystemExit):
            load_results(p)


# ---------------------------------------------------------------------
# find_hits
# ---------------------------------------------------------------------
class TestFindHits:
    def test_single_id_single_hit(self):
        log = "2026-05-28 dns query for abc123def.attacker.com from 1.2.3.4"
        hits = find_hits({"abc123def"}, log)
        assert "abc123def" in hits
        assert len(hits["abc123def"]) == 1

    def test_multiple_ids_separate_hits(self):
        log = (
            "abc111 dns lookup\n"
            "def222 http request\n"
            "abc111 dns lookup again\n"
        )
        hits = find_hits({"abc111", "def222"}, log)
        assert len(hits["abc111"]) == 2
        assert len(hits["def222"]) == 1

    def test_no_match_empty(self):
        hits = find_hits({"abc123"}, "nothing here matches")
        assert hits == {}

    def test_empty_log_empty_result(self):
        assert find_hits({"abc"}, "") == {}

    def test_empty_ids_empty_result(self):
        assert find_hits(set(), "abc def ghi") == {}


# ---------------------------------------------------------------------
# correlate
# ---------------------------------------------------------------------
class TestCorrelate:
    def test_maps_oob_id_back_to_result(self):
        results = [
            {"label": "sniper pos=0 value='admin'", "oob_id": "aaa111",
             "status": 200},
            {"label": "sniper pos=0 value='guest'", "oob_id": "bbb222",
             "status": 200},
        ]
        hits = {"aaa111": ["dns lookup for aaa111.evil.com"]}
        out = correlate(results, hits)
        assert len(out) == 1
        assert out[0]["label"] == "sniper pos=0 value='admin'"
        assert out[0]["oob_id"] == "aaa111"
        assert out[0]["status"] == 200

    def test_no_hits_empty(self):
        results = [{"label": "x", "oob_id": "abc"}]
        assert correlate(results, {}) == []

    def test_unknown_oob_id_handled(self):
        # Hit for an oob_id that isn't in results - should still
        # produce an entry with a placeholder label rather than
        # silently dropping it.
        out = correlate(results=[], hits={"xyz": ["lookup for xyz"]})
        assert len(out) == 1
        assert "<unknown" in out[0]["label"]
