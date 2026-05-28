"""
_common.py
==========
Small utilities shared by the tools in this repo:

  * Color helpers (ANSI escapes; gracefully degrade when stdout is not
    a TTY or NO_COLOR is set, so output stays clean when piped/redirected).
  * Progress iterator (tqdm progress bar with graceful fallback if
    tqdm isn't installed - the scripts still work, you just don't get
    the bar).
  * A printf-style helper that combines the two for "[HIT] ..." lines.

This module is import-only - it has no side effects and no CLI.
"""

import os
import sys


# ---------------------------------------------------------------------
# COLOR
# ---------------------------------------------------------------------
# Standard ANSI SGR codes. We use a small set: red for failures/errors,
# green for hits/success, yellow for warnings, cyan for info/status,
# bold for emphasis. The RESET sequence (0m) restores the terminal's
# default colors after the styled text - without it, every later line
# would inherit our color.
class _Code:
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def color_enabled() -> bool:
    """
    Decide whether to emit ANSI color codes.

    We disable colors when:
      * NO_COLOR env var is set (the de-facto cross-tool convention
        for users who want zero ANSI in any tool's output).
      * stdout isn't a TTY - e.g. piped to a file or another command.
        ANSI codes in a file would just look like garbage when
        someone less'es it later.

    Both checks together cover the common "I'm running this from a
    real terminal vs scripting around it" distinction.
    """
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _wrap(code: str, text: str) -> str:
    """Wrap text in an ANSI code if colors are on, else return as-is."""
    if not color_enabled():
        return text
    return f"{code}{text}{_Code.RESET}"


def red(s: str) -> str:    return _wrap(_Code.RED, s)
def green(s: str) -> str:  return _wrap(_Code.GREEN, s)
def yellow(s: str) -> str: return _wrap(_Code.YELLOW, s)
def cyan(s: str) -> str:   return _wrap(_Code.CYAN, s)
def bold(s: str) -> str:   return _wrap(_Code.BOLD, s)
def dim(s: str) -> str:    return _wrap(_Code.DIM, s)


# ---------------------------------------------------------------------
# PROGRESS BAR
# ---------------------------------------------------------------------
# `tqdm` gives you a live-updating progress bar for any iterable. It's
# optional - we don't want a hard dependency just for cosmetic output.
# When tqdm isn't installed, `progress()` returns the iterable
# unchanged and the script runs the same, just without the bar.
try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False


def progress(iterable, total: int | None = None, desc: str = "", unit: str = "req"):
    """
    Wrap an iterable in a tqdm progress bar if tqdm is available.

    For futures-as-completed-style loops, pass `total=len(futures)`
    so the bar can show "47/101" instead of just spinning. When tqdm
    isn't installed, this is just `return iterable` - same behavior,
    no bar.

    We disable the bar when stdout isn't a TTY (same reasoning as
    with colors - don't pollute a log file with carriage returns).
    """
    if not _HAS_TQDM or not sys.stdout.isatty():
        return iterable
    return _tqdm(iterable, total=total, desc=desc, unit=unit,
                 # leave=False removes the bar from the screen after
                 # completion; cleaner when followed by a summary print.
                 leave=False)


# ---------------------------------------------------------------------
# LINE-PREFIX HELPERS
# ---------------------------------------------------------------------
# Centralizing the "[HIT]" / "[err]" / "[*]" prefixes here keeps the
# styling consistent across scripts: any change (e.g. swap green for
# bold green) propagates everywhere.
def tag_hit() -> str:    return green("[HIT]")
def tag_miss() -> str:   return dim("[   ]")
def tag_info() -> str:   return cyan("[*]")
def tag_ok() -> str:     return green("[+]")
def tag_warn() -> str:   return yellow("[!]")
def tag_err() -> str:    return red("[-]")
def tag_debug() -> str:  return dim("[debug]")
