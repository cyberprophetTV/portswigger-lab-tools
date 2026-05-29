"""
Tests for privesc.py - the classify() decision logic.
"""
from privesc import classify, VERDICTS


# A pair of clearly-different bodies for tests that don't care about
# similarity specifically.
DIFF_A = "<html>admin dashboard</html>"
DIFF_B = "<html>access denied</html>"

# A pair that's IDENTICAL (similarity 1.0).
SAME = "<html>shared content</html>"


class TestClassify:
    def test_idor_likely_when_both_200_and_similar(self):
        verdict, sim = classify(200, SAME, 200, SAME, idor_threshold=0.9)
        assert verdict == "IDOR_LIKELY"
        assert sim == 1.0

    def test_content_delta_when_both_200_but_different(self):
        verdict, sim = classify(200, DIFF_A, 200, DIFF_B, idor_threshold=0.9)
        assert verdict == "CONTENT_DELTA"

    def test_expected_block_when_admin_ok_user_blocked(self):
        for blocked in (401, 403, 302, 303):
            verdict, _ = classify(200, "admin", blocked, "", idor_threshold=0.9)
            assert verdict == "EXPECTED_BLOCK", \
                f"status {blocked} should classify as EXPECTED_BLOCK"

    def test_bypass_when_admin_blocked_user_ok(self):
        for blocked in (401, 403, 302):
            verdict, _ = classify(blocked, "", 200, "user", idor_threshold=0.9)
            assert verdict == "BYPASS"

    def test_both_blocked(self):
        verdict, _ = classify(403, "", 401, "", idor_threshold=0.9)
        assert verdict == "BOTH_BLOCKED"

    def test_status_delta_for_unusual_combos(self):
        # 500 vs 200 - not in the standard ok/blocked buckets
        verdict, _ = classify(500, "", 200, "x", idor_threshold=0.9)
        assert verdict == "STATUS_DELTA"

    def test_threshold_boundary(self):
        # Two strings that are similar but not identical. We control
        # the threshold and verify both sides of the boundary.
        a = "x" * 100
        b = "x" * 90 + "y" * 10   # ~0.9 similar
        # Above the threshold -> IDOR_LIKELY
        verdict_low, _ = classify(200, a, 200, b, idor_threshold=0.5)
        assert verdict_low == "IDOR_LIKELY"
        # Below the threshold -> CONTENT_DELTA
        verdict_high, _ = classify(200, a, 200, b, idor_threshold=0.99)
        assert verdict_high == "CONTENT_DELTA"


class TestVerdicts:
    def test_required_keys(self):
        # The verdicts the classifier emits must all have entries in
        # the VERDICTS dict (used for severity/color/description).
        emitted = {
            "IDOR_LIKELY", "CONTENT_DELTA", "BYPASS",
            "EXPECTED_BLOCK", "BOTH_BLOCKED", "STATUS_DELTA",
        }
        for v in emitted:
            assert v in VERDICTS, f"verdict {v!r} missing from VERDICTS dict"

    def test_high_severity_for_real_findings(self):
        # IDOR_LIKELY and BYPASS are the actual exploitable findings -
        # they MUST be high severity so they stand out in the output.
        assert VERDICTS["IDOR_LIKELY"][0] == "high"
        assert VERDICTS["BYPASS"][0] == "high"
