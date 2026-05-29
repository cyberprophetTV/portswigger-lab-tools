"""
Tests for security_audit.py header/cookie auditors.
"""
from security_audit import (
    audit_required_headers, audit_cookies, audit_disclosure,
    REQUIRED_HEADERS, DISCLOSURE_HEADERS,
)


class TestRequiredHeaders:
    def test_all_present_no_findings(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        assert audit_required_headers(headers) == []

    def test_missing_csp_flags_high(self):
        findings = audit_required_headers({})
        csp = [f for f in findings if "Content-Security-Policy" in f.title]
        assert len(csp) == 1
        assert csp[0].severity == "high"

    def test_missing_all_flags_each(self):
        findings = audit_required_headers({})
        # One finding per required header
        assert len(findings) == len(REQUIRED_HEADERS)

    def test_xcontenttypeoptions_must_be_nosniff(self):
        findings = audit_required_headers({"X-Content-Type-Options": "anything"})
        # Should flag because value isn't nosniff
        bad = [f for f in findings if "not 'nosniff'" in f.title]
        assert len(bad) == 1

    def test_xframeoptions_weak_value_flagged(self):
        findings = audit_required_headers({"X-Frame-Options": "ALLOWALL"})
        bad = [f for f in findings if "X-Frame-Options" in f.title
               and "not DENY" in f.title]
        assert len(bad) == 1

    def test_xframeoptions_deny_accepted(self):
        findings = audit_required_headers({"X-Frame-Options": "DENY"})
        bad = [f for f in findings if "not DENY" in f.title]
        assert len(bad) == 0

    def test_short_hsts_max_age_flagged(self):
        findings = audit_required_headers({
            "Strict-Transport-Security": "max-age=1000"
        })
        bad = [f for f in findings if "max-age" in f.title.lower()]
        assert len(bad) == 1
        assert bad[0].severity == "low"

    def test_case_insensitive_header_lookup(self):
        # CSP present under lowercase key - should be detected as
        # present (no missing finding).
        findings = audit_required_headers({"content-security-policy": "default-src *"})
        missing_csp = [f for f in findings if "missing Content-Security" in f.title]
        assert len(missing_csp) == 0


class TestCookies:
    def test_secure_httponly_samesite_strict_clean(self):
        # A fully-locked-down cookie produces zero findings.
        findings = audit_cookies(["sid=abc; Secure; HttpOnly; SameSite=Strict"])
        assert findings == []

    def test_missing_httponly_flagged(self):
        findings = audit_cookies(["sid=abc; Secure; SameSite=Lax"])
        bad = [f for f in findings if "no HttpOnly" in f.title]
        assert len(bad) == 1
        assert bad[0].severity == "high"

    def test_missing_secure_flagged(self):
        findings = audit_cookies(["sid=abc; HttpOnly; SameSite=Strict"])
        bad = [f for f in findings if "no Secure" in f.title]
        assert len(bad) == 1
        assert bad[0].severity == "high"

    def test_missing_samesite_flagged(self):
        findings = audit_cookies(["sid=abc; Secure; HttpOnly"])
        bad = [f for f in findings if "SameSite" in f.title]
        assert len(bad) == 1
        assert bad[0].severity == "medium"

    def test_samesite_none_treated_as_missing(self):
        # SameSite=None is permissive - we want Strict or Lax for CSRF protection.
        findings = audit_cookies(["sid=abc; Secure; HttpOnly; SameSite=None"])
        bad = [f for f in findings if "SameSite" in f.title]
        assert len(bad) == 1


class TestDisclosure:
    def test_server_header_flagged(self):
        findings = audit_disclosure({"Server": "Apache/2.4.41 (Ubuntu)"})
        assert len(findings) == 1
        assert findings[0].category == "disclosure"
        assert findings[0].severity == "info"
        assert "Apache" in findings[0].title

    def test_powered_by_flagged(self):
        findings = audit_disclosure({"X-Powered-By": "PHP/7.4.3"})
        assert len(findings) == 1

    def test_unknown_headers_ignored(self):
        # Random headers shouldn't trigger disclosure findings.
        findings = audit_disclosure({"X-Custom-Header": "foo"})
        assert findings == []

    def test_case_insensitive(self):
        findings = audit_disclosure({"server": "nginx/1.18"})
        assert len(findings) == 1
