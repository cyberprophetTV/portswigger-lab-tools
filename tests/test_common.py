"""
Tests for _common.py - color helpers and progress wrapper.
"""
import os
import sys
from unittest.mock import patch

from _common import (
    color_enabled, red, green, yellow, _Code,
    tag_hit, tag_info, tag_err, progress,
)


class TestColorEnabled:
    def test_disabled_when_not_tty(self):
        with patch.object(sys.stdout, "isatty", lambda: False):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("NO_COLOR", None)
                assert color_enabled() is False

    def test_disabled_when_no_color_env(self):
        with patch.object(sys.stdout, "isatty", lambda: True):
            with patch.dict(os.environ, {"NO_COLOR": "1"}):
                assert color_enabled() is False

    def test_enabled_when_tty_and_no_env(self):
        with patch.object(sys.stdout, "isatty", lambda: True):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("NO_COLOR", None)
                assert color_enabled() is True


class TestColorWrappers:
    def test_no_codes_when_disabled(self):
        with patch.object(sys.stdout, "isatty", lambda: False):
            assert red("hi") == "hi"
            assert green("hi") == "hi"
            assert yellow("hi") == "hi"

    def test_emits_codes_when_enabled(self):
        with patch.object(sys.stdout, "isatty", lambda: True):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("NO_COLOR", None)
                assert _Code.RED in red("hi")
                assert _Code.GREEN in green("hi")
                assert _Code.RESET in red("hi")


class TestTags:
    def test_tags_contain_expected_text(self):
        # Regardless of color, the bracketed text should be present.
        assert "[HIT]" in tag_hit()
        assert "[*]" in tag_info()
        assert "[-]" in tag_err()


class TestProgress:
    def test_returns_iterable_unchanged_when_no_tty(self):
        # Without tqdm or without a TTY, progress() returns the
        # iterable as-is - iteration still works.
        with patch.object(sys.stdout, "isatty", lambda: False):
            items = list(progress(range(5), total=5))
            assert items == [0, 1, 2, 3, 4]
