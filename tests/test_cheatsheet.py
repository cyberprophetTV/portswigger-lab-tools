"""
Tests for cheatsheet.py - catalog integrity + search.
TUI loop is interactive, tested manually.
"""
import pytest

pytest.importorskip("rich")
pytest.importorskip("questionary")

from cheatsheet import (
    CHEATSHEET, CheatCategory, CheatEntry, search_all, render_entry,
)


class TestCatalogIntegrity:
    def test_at_least_15_categories(self):
        # If someone deletes most of the cheat sheet, fail loudly.
        assert len(CHEATSHEET) >= 15

    def test_every_category_has_entries(self):
        for cat in CHEATSHEET:
            assert cat.entries, f"category {cat.name!r} has no entries"

    def test_every_entry_has_payload_and_when(self):
        for cat in CHEATSHEET:
            for entry in cat.entries:
                assert entry.title, f"{cat.name}: entry has no title"
                assert entry.payload, f"{cat.name}/{entry.title}: no payload"
                assert entry.when, f"{cat.name}/{entry.title}: no 'when' context"

    def test_no_duplicate_category_names(self):
        names = [c.name for c in CHEATSHEET]
        assert len(names) == len(set(names))

    def test_no_duplicate_entry_titles_within_a_category(self):
        for cat in CHEATSHEET:
            titles = [e.title for e in cat.entries]
            assert len(titles) == len(set(titles)), \
                f"duplicate titles in {cat.name}"


class TestExpectedCategoriesPresent:
    # If any of these go missing, the cheatsheet is no longer covering
    # the BSCP exam essentials. Hard-failure on omission.
    @pytest.mark.parametrize("name", [
        "SQL Injection", "XSS - Cross-Site Scripting",
        "SSRF - Server-Side Request Forgery", "JWT Attacks",
        "OS Command Injection", "Template Injection (SSTI)",
        "File Upload", "XXE - XML External Entity",
        "CSRF", "Path Traversal", "Open Redirect",
        "Web Cache Poisoning", "Deserialization (Java + PHP)",
        "NoSQL Injection (MongoDB-flavored)", "LDAP Injection",
        "Race Condition",
    ])
    def test_category_present(self, name):
        assert any(c.name == name for c in CHEATSHEET), \
            f"missing expected category: {name!r}"


class TestSearch:
    def test_finds_known_term(self):
        # 'time-based' must surface SQLi blind entries.
        matches = search_all("time-based")
        assert len(matches) >= 2
        assert any("SQL" in cat.name for cat, _ in matches)

    def test_finds_jwt(self):
        matches = search_all("jwt")
        assert len(matches) >= 3   # we have multiple JWT-flavored entries

    def test_searches_payload_content(self):
        # A payload-only term (the AWS metadata IP) should still match.
        matches = search_all("169.254.169.254")
        assert len(matches) >= 1
        assert any("SSRF" in cat.name for cat, _ in matches)

    def test_case_insensitive(self):
        a = search_all("XSS")
        b = search_all("xss")
        assert len(a) == len(b)

    def test_no_match_returns_empty(self):
        assert search_all("zzzzzthisisnotanything") == []


class TestRenderSmokeTest:
    def test_render_every_entry_does_not_crash(self):
        # Smoke: render_entry should produce output for every catalog
        # entry without raising. Catches markup syntax errors etc.
        import io
        from rich.console import Console
        from cheatsheet import THEME
        for cat in CHEATSHEET:
            for entry in cat.entries:
                c = Console(theme=THEME, file=io.StringIO(),
                              force_terminal=True, width=120)
                render_entry(c, cat, entry)
                out = c.file.getvalue()
                assert entry.title in out, \
                    f"render output missing title: {cat.name}/{entry.title}"
