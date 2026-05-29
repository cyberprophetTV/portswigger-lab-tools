"""
Tests for lab_tools.py - covers the non-interactive pieces:
  - TOOLS catalog validity (every entry resolves to an existing script,
    has a description, etc.)
  - build_command produces the right argv from a prompt-answers dict
  - THEMES catalog has all the keys we depend on at every level
"""
from pathlib import Path

import pytest

# These imports will fail if rich/questionary aren't installed; the
# CI workflow installs them. Locally, `pip install rich questionary`.
pytest.importorskip("rich")
pytest.importorskip("questionary")

import lab_tools
from lab_tools import (
    TOOLS, THEMES, Tool, Prompt, build_command, check_paths, RuleTracker,
    parse_motivation, render_motivation_quote, render_motivation_full,
    render_vuln_matrix, TOOL_CATEGORIES,
)


REPO_ROOT = Path(__file__).parent.parent


class TestToolCatalog:
    def test_no_duplicate_keys(self):
        keys = [t.key for t in TOOLS]
        assert len(keys) == len(set(keys))

    def test_no_duplicate_names(self):
        names = [t.name for t in TOOLS]
        assert len(names) == len(set(names))

    def test_every_script_exists(self):
        for t in TOOLS:
            script = REPO_ROOT / t.script
            assert script.exists(), f"missing script for tool {t.key!r}: {t.script}"

    def test_every_tool_has_description(self):
        for t in TOOLS:
            assert len(t.description) > 20, f"description too short for {t.key!r}"

    def test_every_tool_has_prompts_or_is_pure_tui(self):
        # Most tools take CLI args -> need prompts. But a few are
        # pure-TUI launchers (cheatsheet) that take no args at all;
        # those legitimately have empty prompts.
        pure_tui_keys = {"cheatsheet"}
        for t in TOOLS:
            if t.key in pure_tui_keys:
                continue
            assert len(t.prompts) > 0, \
                f"non-TUI tool {t.key!r} has no prompts - " \
                "did you forget to add them?"


class TestThemes:
    REQUIRED_STYLES = {
        "primary", "accent", "success", "warning", "error",
        "muted", "banner", "url", "kbd",
    }

    def test_all_themes_have_all_required_styles(self):
        for name, theme in THEMES.items():
            keys = set(theme.styles.keys())
            missing = self.REQUIRED_STYLES - keys
            assert not missing, f"theme {name!r} missing styles: {missing}"

    def test_named_themes_present(self):
        # The launcher offers these specific themes; if one disappears
        # the menu would crash.
        assert "neon" in THEMES
        assert "matrix" in THEMES
        assert "monochrome" in THEMES


class TestBuildCommand:
    def test_positional_args_in_order(self):
        tool = Tool(
            key="test", name="test", script="script.py",
            description="x" * 30, lab_url=None,
            prompts=[
                Prompt("first",  "?"),
                Prompt("second", "?"),
                Prompt("third",  "?"),
            ],
        )
        cmd = build_command(tool, {"first": "A", "second": "B", "third": "C"})
        # cmd[0] is python interpreter, cmd[1] is script
        assert cmd[2:] == ["A", "B", "C"]

    def test_flag_args_become_flag_value_pairs(self):
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[
                Prompt("base", "?"),
                Prompt("--workers", "?", default="10"),
                Prompt("--proxy", "?", default="burp"),
            ],
        )
        cmd = build_command(tool, {
            "base": "https://x.com",
            "--workers": "20",
            "--proxy": "http://1.2.3.4:8080",
        })
        assert "https://x.com" in cmd
        assert cmd[cmd.index("--workers") + 1] == "20"
        assert cmd[cmd.index("--proxy") + 1] == "http://1.2.3.4:8080"

    def test_positional_before_flag(self):
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[
                Prompt("--flag", "?"),
                Prompt("pos", "?"),     # declared second but should still be first in argv
            ],
        )
        cmd = build_command(tool, {"pos": "P", "--flag": "F"})
        # Positional 'P' comes before '--flag F' regardless of declaration order
        assert cmd.index("P") < cmd.index("--flag")

    def test_extra_args_appended_and_split(self):
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[Prompt("base", "?")],
        )
        cmd = build_command(tool, {
            "base": "x",
            "__extra": "--verbose --proxy 'http://my proxy:8080'",
        })
        assert "--verbose" in cmd
        # shlex.split handles the quoted proxy URL correctly
        assert "http://my proxy:8080" in cmd

    def test_skipped_optional_arg_not_in_cmd(self):
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[
                Prompt("base", "?"),
                Prompt("--maybe", "?", required=False),
            ],
        )
        # User didn't provide --maybe; it's absent from the answers dict
        cmd = build_command(tool, {"base": "x"})
        assert "--maybe" not in cmd


# ---------------------------------------------------------------------
# RENDER SMOKE TESTS
# ---------------------------------------------------------------------
# Regression for a real bug: show_banner used to be called with a
# theme-less Console, but the banner content uses style names like
# `primary` that only resolve via a Theme. Render-time crash on first
# launch. These tests render the banner under every theme to catch
# any such style mismatch before it ships.
class TestCheckPaths:
    def test_empty_when_all_paths_exist(self, tmp_path):
        f = tmp_path / "exists.txt"
        f.write_text("x")
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[Prompt("file", "?", kind="path")],
        )
        assert check_paths(tool, {"file": str(f)}) == []

    def test_returns_missing(self, tmp_path):
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[Prompt("file", "?", kind="path")],
        )
        bad = str(tmp_path / "does-not-exist.txt")
        missing = check_paths(tool, {"file": bad})
        assert len(missing) == 1
        assert missing[0][0].arg == "file"

    def test_ignores_non_path_prompts(self):
        # A text-kind prompt with a value that doesn't look like a real
        # file shouldn't trigger a missing-file error.
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[Prompt("base_url", "?", kind="text")],
        )
        assert check_paths(tool, {"base_url": "https://example.com"}) == []

    def test_skipped_path_prompts_not_checked(self, tmp_path):
        # If the user left an optional path prompt blank, we shouldn't
        # claim a missing file for it.
        tool = Tool(
            key="t", name="t", script="s.py", description="x" * 30, lab_url=None,
            prompts=[Prompt("file", "?", kind="path", required=False)],
        )
        assert check_paths(tool, {}) == []

    def test_every_default_file_exists(self):
        # Sanity check across EVERY tool: any path-kind prompt with a
        # default value must point at a file that's actually in the
        # repo. Catches "I added a Prompt default but forgot to commit
        # the file" mistakes for ALL tools, not just intruder.
        for t in TOOLS:
            for p in t.prompts:
                if p.kind == "path" and p.default:
                    path = Path(__file__).parent.parent / p.default
                    assert path.exists(), \
                        f"tool {t.key!r}: missing default file {p.default!r}"


class TestRuleTracker:
    def test_empty_tracker_is_not_stuck(self):
        t = RuleTracker(time_limit_minutes=15.0)
        assert not t.is_stuck("any_tool")
        assert t.total_seconds() == 0

    def test_records_per_tool_time(self):
        t = RuleTracker()
        t.record("intruder", 60.0)
        t.record("intruder", 30.0)
        t.record("workflow", 10.0)
        assert t.spent["intruder"] == 90.0
        assert t.spent["workflow"] == 10.0
        assert t.runs["intruder"] == 2
        assert t.runs["workflow"] == 1
        assert t.total_seconds() == 100.0

    def test_stuck_threshold(self):
        t = RuleTracker(time_limit_minutes=1.0)   # 60-second threshold
        t.record("intruder", 30.0)
        assert not t.is_stuck("intruder")
        t.record("intruder", 31.0)        # cumulative 61 - over threshold
        assert t.is_stuck("intruder")

    def test_other_tool_not_marked_stuck(self):
        # Only the tool that exceeded the threshold is "stuck", not
        # other tools that have separate accumulators.
        t = RuleTracker(time_limit_minutes=1.0)
        t.record("intruder", 120.0)
        t.record("workflow", 5.0)
        assert t.is_stuck("intruder")
        assert not t.is_stuck("workflow")

    def test_render_does_not_crash_under_themes(self):
        # Smoke test - tracker.render should produce output without
        # exception under every defined theme.
        import io
        from rich.console import Console
        t = RuleTracker(time_limit_minutes=1.0)
        t.record("intruder", 70.0)        # stuck
        t.record("workflow", 5.0)         # not stuck
        for theme_name in THEMES:
            console = Console(theme=THEMES[theme_name], file=io.StringIO(),
                                force_terminal=True, width=120)
            t.render(console)
            out = console.file.getvalue()
            assert "intruder" in out
            assert "workflow" in out
            # The stuck warning text should appear for intruder
            assert "stuck" in out

    def test_render_skipped_when_no_runs(self):
        import io
        from rich.console import Console
        t = RuleTracker()
        console = Console(theme=THEMES["neon"], file=io.StringIO(),
                            force_terminal=True, width=80)
        t.render(console)
        # Nothing recorded -> nothing rendered.
        assert console.file.getvalue() == ""


class TestToolCategories:
    def test_every_tool_has_known_category(self):
        # A typo in `category="actvie"` would silently break the
        # color-coding. Hard-check the value against TOOL_CATEGORIES.
        for t in TOOLS:
            assert t.category in TOOL_CATEGORIES, \
                f"tool {t.key!r} has unknown category {t.category!r}"

    def test_all_four_categories_used(self):
        # Sanity that we ACTUALLY use all 4 categories - if everyone's
        # "active" the color-coding adds noise without signal.
        used = {t.category for t in TOOLS}
        for required in TOOL_CATEGORIES:
            assert required in used, \
                f"no tool uses category {required!r} - either categorize one " \
                f"or remove the category from TOOL_CATEGORIES"

    def test_each_category_has_style_label_abbrev(self):
        for name, info in TOOL_CATEGORIES.items():
            assert "style" in info,  f"{name} missing style"
            assert "label" in info,  f"{name} missing label"
            assert "abbrev" in info, f"{name} missing abbrev"
            # Abbreviations should be short to fit the menu prefix.
            assert len(info["abbrev"]) <= 4, \
                f"{name} abbrev too long: {info['abbrev']!r}"


class TestVulnerabilityMapping:
    def test_every_tool_has_vulnerabilities(self):
        # Cheatsheet's coverage is the catch-all entry ("ALL classes -
        # reference for..."), so it counts. Every other tool should
        # have at least one specific vuln-class entry.
        for t in TOOLS:
            assert t.vulnerabilities, \
                f"tool {t.key!r} has no vulnerabilities listed"

    def test_no_empty_strings_in_vuln_list(self):
        for t in TOOLS:
            for v in t.vulnerabilities:
                assert v.strip(), f"{t.key}: empty string in vulnerabilities"

    def test_render_vuln_matrix_does_not_crash(self):
        import io
        from rich.console import Console
        # Render under each theme.
        for theme_name in THEMES:
            console = Console(theme=THEMES[theme_name], file=io.StringIO(),
                                force_terminal=True, width=200)
            render_vuln_matrix(console)
            out = console.file.getvalue()
            # Every tool name should appear in the rendered matrix.
            for t in TOOLS:
                assert t.name in out, \
                    f"matrix missing tool {t.name!r} under theme {theme_name!r}"


class TestParseMotivation:
    def test_basic_paragraph(self):
        text = "I'm earning BSCP to land an AppSec job."
        assert parse_motivation(text) == [
            "I'm earning BSCP to land an AppSec job."
        ]

    def test_bullet_per_quote(self):
        text = (
            "- I've passed harder things before.\n"
            "- Every solved lab is one step closer.\n"
            "- 15 min stuck = switch angle, don't dig.\n"
        )
        quotes = parse_motivation(text)
        assert len(quotes) == 3
        assert "I've passed harder things before." in quotes

    def test_ignores_comments(self):
        # `# ...` lines are doc comments, not motivation.
        text = (
            "# This is a doc comment, do not show.\n"
            "Real reason: change my career.\n"
            "# Another comment.\n"
        )
        quotes = parse_motivation(text)
        assert quotes == ["Real reason: change my career."]

    def test_ignores_section_headers(self):
        # `## ...` are section headers (rendered separately in full view).
        text = (
            "## My goal\n"
            "Pass BSCP and get hired.\n"
            "## When stuck\n"
            "- Switch angle.\n"
        )
        quotes = parse_motivation(text)
        assert "Pass BSCP and get hired." in quotes
        assert "Switch angle." in quotes
        # The header itself isn't quoted.
        assert "## My goal" not in quotes
        assert "My goal" not in quotes

    def test_multiline_paragraph_joined(self):
        text = (
            "The cert is a CONCRETE thing I can hand a hiring manager\n"
            "that proves I can do the work, not just talk about it.\n"
        )
        quotes = parse_motivation(text)
        assert len(quotes) == 1
        # Joined with spaces (no double-space, no newline preserved).
        assert "hiring manager that proves" in quotes[0]

    def test_blank_lines_separate_paragraphs(self):
        text = "First paragraph.\n\nSecond paragraph.\n"
        quotes = parse_motivation(text)
        assert quotes == ["First paragraph.", "Second paragraph."]

    def test_template_placeholders_filtered_out(self):
        # `[fill me in]` style placeholders are dropped so an unedited
        # template doesn't surface its TODOs.
        text = (
            "- [your current role]\n"
            "- [list one specific thing]\n"
            "- This is a real motivation that should survive.\n"
        )
        quotes = parse_motivation(text)
        assert quotes == ["This is a real motivation that should survive."]

    def test_short_lines_filtered_out(self):
        # 5-character "yes" or "no" lines aren't really motivation -
        # the parser drops anything < 6 chars to avoid noise.
        text = "- yes\n- This one is long enough to count.\n"
        quotes = parse_motivation(text)
        assert "yes" not in quotes
        assert "This one is long enough to count." in quotes

    def test_empty_file_returns_empty_list(self):
        assert parse_motivation("") == []
        assert parse_motivation("\n\n  \n") == []

    def test_only_comments_returns_empty(self):
        text = "# All comments.\n# Nothing real.\n## Just a header\n"
        assert parse_motivation(text) == []


class TestMotivationRender:
    def _console(self):
        import io
        from rich.console import Console
        return Console(theme=THEMES["neon"], file=io.StringIO(),
                        force_terminal=True, width=100)

    def test_render_quote_with_empty_list_is_noop(self):
        # Don't print an empty panel when there's no motivation set up.
        c = self._console()
        render_motivation_quote(c, [])
        assert c.file.getvalue() == ""

    def test_render_quote_with_one_quote_prints_panel(self):
        c = self._console()
        render_motivation_quote(c, ["The reason matters."])
        out = c.file.getvalue()
        assert "The reason matters." in out
        assert "why I'm doing this" in out


class TestBannerRender:
    @pytest.mark.parametrize("theme_name", list(THEMES.keys()))
    def test_show_banner_does_not_crash(self, theme_name):
        import io
        from rich.console import Console as RichConsole
        # `record=True` + force_terminal makes the console capture
        # styled output to a buffer instead of writing to a real TTY.
        console = RichConsole(
            theme=THEMES[theme_name],
            file=io.StringIO(),
            force_terminal=True,
            width=80,
        )
        # Should not raise.
        lab_tools.show_banner(console)
        # Sanity-check: the buffer should contain our project name.
        output = console.file.getvalue()
        assert "portswigger" in output
        assert "lab-tools" in output
