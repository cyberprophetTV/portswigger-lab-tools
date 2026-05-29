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
from lab_tools import TOOLS, THEMES, Tool, Prompt, build_command


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

    def test_every_tool_has_at_least_one_prompt(self):
        for t in TOOLS:
            assert len(t.prompts) > 0


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
