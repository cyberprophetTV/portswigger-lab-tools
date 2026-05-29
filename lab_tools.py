#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY.
# Intended for solving PortSwigger Web Security Academy labs and for
# use against systems you OWN or have EXPLICIT WRITTEN PERMISSION to
# test. Running this against unauthorized systems is illegal in most
# jurisdictions. See README.
"""
=====================================================================
lab_tools.py - Interactive launcher / menu for the toolkit
=====================================================================

WHAT THIS IS
------------
A friendly TUI (text user interface) that gives you a menu of every
tool in the repo, prompts for the inputs each one needs, and runs the
selected tool for you. It's an alternative entry point to the
individual CLI scripts - same outcome, different ergonomics.

  $ python3 lab_tools.py            # interactive launcher
  $ python3 username_enum_solver.py LAB_URL ...   # direct CLI

If you're scripting, use the direct CLI. If you're exploring the
toolkit or you forget the exact flags, use the launcher.

TUI vs CLI - WHAT'S THE DIFFERENCE?
-----------------------------------
A CLI ("command line interface") takes its inputs as arguments on a
single shell command. You type the whole thing up front, hit enter,
the program runs and exits. Great for scripting, automation, and
power users who already know the commands.

A TUI ("text user interface") draws on the terminal interactively -
menus, prompts, panels, sometimes mouse support. You navigate with
the keyboard. Examples: htop, vim, lazygit, nethack. TUIs are
discoverable (you can see your options) but harder to automate.

This launcher is a SIMPLE TUI - it's not a full-screen interactive
app like htop. It just prints a banner, shows menus, prompts for
inputs, and dispatches. Think of it as "guided CLI."

THE LIBRARIES
-------------
We use two third-party libraries to make this look good:

  rich
      The de-facto standard for nice terminal output in Python.
      Provides Console (smart print()), Panel (boxed text),
      Table (formatted columns), Text (styled strings), Theme
      (color-scheme objects), Progress (progress bars), and a
      ton more. Author also wrote Textual (full TUI framework).
      Install: pip install rich

  questionary
      Interactive prompts built on prompt_toolkit. Gives you
      arrow-key-navigable select menus, autocompleting text
      inputs, yes/no confirmations, etc. Used by Poetry and
      a bunch of other CLI tools.
      Install: pip install questionary

Both are OPTIONAL for the rest of the toolkit but REQUIRED for
this launcher. If they're missing the launcher fails fast with
a clear install message rather than mysteriously breaking.

THEMES
------
A "theme" is a named mapping from semantic style roles (e.g.
"primary", "success", "warning") to concrete colors. Decoupling
roles from colors lets us swap the whole color scheme by picking
a different theme - the code never hardcodes "green", it uses
"success" and the theme decides what color success looks like.

This launcher ships with three themes:
  neon        cyan/magenta/green - punchy, dark-terminal default
  matrix      all-green - classic "hacker movie" aesthetic
  monochrome  no color - for accessibility, screen readers,
              or terminals where colors look bad

You're prompted to pick one on first launch.

THE LAUNCHER'S DESIGN
---------------------
We declare each tool as a Tool dataclass: name, script path,
description, lab URL, list of input prompts. Adding a new tool to
the menu is a single dict literal - no need to touch the menu code.

When the user picks a tool we:
  1. Show its description + the lab URL it targets
  2. Prompt for each input in turn (with sensible defaults)
  3. Optionally take an "extra flags" string for advanced users
  4. Build the equivalent CLI command, SHOW IT to the user
     (educational: now they know how to run it directly next time)
  5. Run the tool via subprocess.run() so its own output streams
     through normally

After the tool exits, we loop back to the main menu.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
import os
import shlex                                 # for quoting CLI args correctly
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---- Optional deps with friendly install message ----
# We import Rich + questionary at module level, but wrap in a try/except
# so a missing dep gives a clear error instead of a cryptic ImportError.
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
    from rich.align import Align
    from rich.padding import Padding
    import questionary
    from questionary import Style as QStyle
except ImportError as e:
    sys.stderr.write(
        f"lab_tools.py needs Rich and questionary:\n"
        f"  pip install rich questionary\n\n"
        f"(missing module: {e.name})\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------
# THEMES
# ---------------------------------------------------------------------
# A Rich Theme is a dict mapping "style names" (strings you can use
# inside Rich markup like [primary]hello[/primary]) to color/attribute
# specs. Themes share the same KEY set so any code that styles via
# "primary" / "success" / etc. works with any theme.
#
# Style spec syntax (Rich):
#   "color"                     foreground color
#   "color on bgcolor"          fg + bg
#   "bold color"                bold + fg
#   "italic dim color"          multi-attribute
THEMES: dict[str, Theme] = {
    # NEON - vibrant default, easy to read on dark backgrounds.
    "neon": Theme({
        "primary":   "bold cyan",
        "accent":    "bold magenta",
        "success":   "bold green",
        "warning":   "bold yellow",
        "error":     "bold red",
        "muted":     "dim white",
        "banner":    "bold cyan",
        "url":       "underline blue",
        "kbd":       "reverse cyan",
    }),
    # MATRIX - all-green, dark background, classic Hollywood hacker.
    "matrix": Theme({
        "primary":   "bold green",
        "accent":    "green",
        "success":   "bold bright_green",
        "warning":   "bold yellow",
        "error":     "bold red",
        "muted":     "dim green",
        "banner":    "bold bright_green",
        "url":       "underline green",
        "kbd":       "reverse green",
    }),
    # MONOCHROME - no color. For screen readers, output redirection,
    # or terminals where colors render badly.
    "monochrome": Theme({
        "primary":   "bold",
        "accent":    "bold",
        "success":   "bold",
        "warning":   "bold",
        "error":     "bold",
        "muted":     "dim",
        "banner":    "bold",
        "url":       "underline",
        "kbd":       "reverse",
    }),
}


def make_questionary_style(theme_name: str) -> QStyle:
    """
    Translate our theme name into a questionary Style.

    Questionary uses prompt_toolkit's class system - you set styles
    by "class name" (e.g. "qmark", "selected") rather than by Rich's
    inline markup. We map our theme palette into the prompt_toolkit
    classes that questionary actually paints with.

    The hex colors below approximate the named colors our Rich theme
    uses - questionary/prompt_toolkit don't read Rich themes directly.
    """
    if theme_name == "matrix":
        return QStyle([
            ("qmark",     "fg:#00ff00 bold"),
            ("question",  "fg:#00ff00 bold"),
            ("answer",    "fg:#00cc00 bold"),
            ("pointer",   "fg:#00ff00 bold"),
            ("highlighted", "fg:#00ff00 bold"),
            ("selected",  "fg:#00ff00"),
            ("separator", "fg:#005500"),
            ("instruction", "fg:#005500"),
        ])
    if theme_name == "monochrome":
        return QStyle([
            ("qmark",     "bold"),
            ("question",  "bold"),
            ("answer",    "bold"),
            ("pointer",   "bold"),
            ("highlighted", "bold"),
        ])
    # neon (default)
    return QStyle([
        ("qmark",     "fg:#00ffff bold"),
        ("question",  "fg:#ffffff bold"),
        ("answer",    "fg:#ff00ff bold"),
        ("pointer",   "fg:#00ffff bold"),
        ("highlighted", "fg:#00ffff bold"),
        ("selected",  "fg:#ff00ff"),
        ("separator", "fg:#555555"),
        ("instruction", "fg:#aaaaaa"),
    ])


# ---------------------------------------------------------------------
# TOOL CATALOG
# ---------------------------------------------------------------------
# Each Tool is a self-describing record: name, the script that
# implements it, what it does, which PortSwigger lab it targets, and
# what inputs the user needs to provide.
#
# A "prompt" is one input the launcher asks the user for. Positional
# args have no flag and become bare arguments to the script.
# Optional flags start with "--" and are passed through as --flag value.
@dataclass
class Prompt:
    arg: str                # arg name; positional like "base_url", or flag like "--workers"
    question: str           # human-readable text shown in the prompt
    default: str | None = None       # default value (Enter to accept)
    kind: str = "text"      # "text" | "select" | "path"
    choices: list[str] = field(default_factory=list)  # for kind="select"
    required: bool = True


@dataclass
class Tool:
    key: str                # short id (used internally)
    name: str               # menu label
    script: str             # filename of the underlying tool
    description: str        # 2-3 line summary shown after selection
    lab_url: str | None     # PortSwigger lab URL, if any
    prompts: list[Prompt]


TOOLS: list[Tool] = [
    Tool(
        key="enum_diff",
        name="Username enum (different responses)",
        script="username_enum_solver.py",
        description=(
            "Two-phase attack: find a valid username by spotting the response "
            "whose body length differs from the rest, then brute-force its "
            "password. Targets labs where invalid/valid usernames produce "
            "obviously different error pages."
        ),
        lab_url="https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses",
        prompts=[
            Prompt("base_url",  "Lab URL (https://...web-security-academy.net)"),
            Prompt("usernames", "Usernames wordlist path", default="usernames.txt", kind="path"),
            Prompt("passwords", "Passwords wordlist path", default="passwords.txt", kind="path"),
        ],
    ),
    Tool(
        key="enum_subtle",
        name="Username enum (subtly different responses)",
        script="subtle_response_solver.py",
        description=(
            "Same goal but for labs where the response only differs by ~1 "
            "character. Uses difflib.SequenceMatcher + CSRF-token "
            "canonicalization to find the outlier when naive length "
            "comparison won't cut it."
        ),
        lab_url="https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses",
        prompts=[
            Prompt("base_url",  "Lab URL"),
            Prompt("usernames", "Usernames wordlist path", default="usernames.txt", kind="path"),
            Prompt("passwords", "Passwords wordlist path", default="passwords.txt", kind="path"),
        ],
    ),
    Tool(
        key="enum_timing",
        name="Username enum (response timing)",
        script="timing_attack_solver.py",
        description=(
            "Detects valid usernames via response-time differences (server "
            "runs bcrypt on a real hash for valid users). Uses a long junk "
            "password to amplify the timing oracle, samples each candidate "
            "N times, and rotates X-Forwarded-For to defeat per-IP rate "
            "limiting."
        ),
        lab_url="https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing",
        prompts=[
            Prompt("base_url",  "Lab URL"),
            Prompt("usernames", "Usernames wordlist path", default="usernames.txt", kind="path"),
            Prompt("passwords", "Passwords wordlist path", default="passwords.txt", kind="path"),
            Prompt("--samples", "Samples per candidate (more = slower, more reliable)", default="3"),
        ],
    ),
    Tool(
        key="privesc",
        name="Privilege-escalation / IDOR comparator (dual cookies)",
        script="privesc.py",
        description=(
            "Replay the same URL list as TWO different cookie jars "
            "(admin + low-priv) and classify each response pair. Flags "
            "IDOR_LIKELY (both 200, similar body), CONTENT_DELTA "
            "(both 200, different), and BYPASS (admin blocked, user "
            "not). Auth-control bug finder."
        ),
        lab_url=None,
        prompts=[
            Prompt("url_list", "File with one URL per line", kind="path"),
            Prompt("--admin-jar", "Admin cookie jar (JSON, blank to skip)",
                   default="", kind="path", required=False),
            Prompt("--user-jar",  "Low-priv cookie jar (JSON, blank to skip)",
                   default="", kind="path", required=False),
        ],
    ),
    Tool(
        key="security_audit",
        name="Security audit (headers + cookies)",
        script="security_audit.py",
        description=(
            "Passive analysis of a URL. Reports missing security headers "
            "(CSP, HSTS, X-Frame-Options, etc.), insecure cookies "
            "(no HttpOnly / Secure / SameSite), and tech-stack disclosure "
            "(Server, X-Powered-By). One GET request; takes seconds."
        ),
        lab_url=None,
        prompts=[
            Prompt("url", "Target URL"),
        ],
    ),
    Tool(
        key="param_miner",
        name="Hidden parameter discovery (param miner)",
        script="param_miner.py",
        description=(
            "Find hidden admin/debug parameters that don't appear in normal "
            "browser traffic. For each name in a wordlist (admin, debug, "
            "role, isAdmin, ...), append it to your request with truthy "
            "values (true/1/admin/yes) and flag responses that diverge "
            "from baseline. Auto-handles URL-encoded and JSON bodies."
        ),
        lab_url=None,
        prompts=[
            Prompt("request_file", "Raw HTTP request template (must include a POST body)",
                   default="examples/login.txt", kind="path"),
            Prompt("--params", "Parameter wordlist",
                   default="hidden-params.txt", kind="path"),
            Prompt("--noise-tolerance", "Ignore length diffs within +/-N bytes "
                                       "(useful for noisy responses)",
                   default="0", required=False),
        ],
    ),
    Tool(
        key="dirbuster",
        name="Content discovery (dirbusting)",
        script="dirbuster.py",
        description=(
            "Find hidden endpoints by trying every path in a wordlist "
            "and flagging the ones the server actually serves. Default "
            "interesting statuses: 200/301/302/401/403/500. Supports "
            "extension fuzzing (.php/.bak/.zip), recursion into "
            "discovered directories, and the same auth + proxy + "
            "output-format options as intruder."
        ),
        lab_url=None,
        prompts=[
            Prompt("base_url", "Target base URL (https://...)"),
            Prompt("wordlist", "Path wordlist (one path per line)",
                   default="common-paths.txt", kind="path"),
            Prompt("--extensions", "Extensions to try (comma-separated, e.g. '.php,.bak')",
                   default="", required=False),
        ],
    ),
    Tool(
        key="intruder",
        name="Intruder (general-purpose fuzzer)",
        script="intruder.py",
        description=(
            "Burp-Intruder-style HTTP request fuzzer. Give it a raw request "
            "template with §MARKER§ payload positions, a wordlist, and an "
            "attack mode (sniper / battering-ram / pitchfork / cluster-bomb). "
            "Use it for SQLi, XSS, path traversal, dir enum, or any other "
            "'swap X into Y' attack."
        ),
        lab_url=None,
        prompts=[
            Prompt("request_file", "Raw HTTP request template file",
                   default="examples/login.txt", kind="path"),
            Prompt("--payload",    "Payload wordlist path", default="usernames.txt", kind="path"),
            Prompt("--mode",       "Attack mode", default="sniper",
                   kind="select",
                   choices=["sniper", "battering-ram", "pitchfork", "cluster-bomb"]),
            Prompt("--match-status", "Match status (e.g. '200', '!403'); blank = no filter",
                   default="", required=False),
            Prompt("--match-length", "Match body length (e.g. '!3168'); blank = no filter",
                   default="", required=False),
        ],
    ),
]


# ---------------------------------------------------------------------
# UI HELPERS
# ---------------------------------------------------------------------
def show_banner(console: Console) -> None:
    """
    Print the project banner: a bordered panel with the project name,
    a one-line tagline, and the educational-use disclaimer.

    Rich.Panel draws a Unicode box around its content. The `border_style`
    pulls from the active theme, so the box color matches the theme.
    """
    title = Text.assemble(
        ("portswigger", "banner"),
        ("-", "muted"),
        ("lab-tools", "banner"),
    )
    body = Text.assemble(
        "Educational pentesting toolkit for the ",
        ("PortSwigger Web Security Academy", "accent"),
        "\n",
        ("FOR EDUCATIONAL USE ONLY", "error"),
        ".  Authorized targets only.\n",
        ("Repo: ", "muted"),
        ("github.com/cyberprophetTV/portswigger-lab-tools", "url"),
    )
    panel = Panel(
        Align.center(body, vertical="middle"),
        title=title,
        border_style="primary",
        padding=(1, 4),
    )
    console.print(panel)


def show_disclaimer_acceptance(console: Console) -> bool:
    """
    Make the user explicitly accept the educational-use disclaimer
    before they can use the launcher. This is the "are you authorized?"
    speed bump that responsible security tools include.

    Returns True if they accepted.
    """
    console.print()
    console.print(
        "[warning]By continuing, you confirm that you are using this tool against "
        "systems you own or have written authorization to test.[/warning]"
    )
    return questionary.confirm(
        "Continue?",
        default=False,
        # `instruction` shows next to the question - here we use it
        # to remind people that the safe answer is "No, I'm not sure".
        instruction="(y/N)",
        auto_enter=False,
    ).ask() is True


def pick_theme(console: Console) -> str:
    """
    Show a small preview of each theme, then let the user pick one.
    The preview is a tiny panel rendered with that theme so they can
    see what they're choosing.
    """
    console.print("[primary]Choose a theme:[/primary]")
    for name in THEMES:
        # Build a one-off Console using this candidate theme so the
        # preview is rendered with the theme's actual colors.
        preview = Console(theme=THEMES[name], width=60, highlight=False)
        sample = Text.assemble(
            ("[+] success message  ", "success"),
            ("[!] warning  ", "warning"),
            ("[-] error  ", "error"),
            ("[*] info", "primary"),
        )
        preview.print(Panel(sample, title=f"theme: {name}", border_style="accent",
                            padding=(0, 1)))

    choice = questionary.select(
        "Theme:",
        choices=list(THEMES.keys()),
        default="neon",
        # `qmark` is the leading icon character; "?" is the default,
        # we use "›" because it reads as a pointer.
        qmark="›",
    ).ask()
    return choice or "neon"


def make_console(theme_name: str) -> Console:
    """
    Build the main Rich Console wired up to the chosen theme.

    `highlight=False` disables Rich's auto-syntax-highlighting of
    numbers/URLs in printed strings - it can look messy in CLI output
    and we want our explicit styling to be the only style applied.
    """
    return Console(theme=THEMES[theme_name], highlight=False)


def show_tool_menu(console: Console) -> Tool | None:
    """Present the main menu of tools + 'Quit'. Returns the chosen Tool, or None to quit."""
    console.print()
    console.print("[primary]Available tools[/primary]")

    # Render a Rich Table summarizing each tool: number, name, script.
    # This is purely informational - the actual selection happens via
    # questionary's arrow-key navigator.
    table = Table(border_style="muted", show_lines=False, padding=(0, 1))
    table.add_column("#",      style="accent",  width=3)
    table.add_column("Tool",   style="primary")
    table.add_column("Script", style="muted")
    for i, t in enumerate(TOOLS, start=1):
        table.add_row(str(i), t.name, t.script)
    console.print(table)

    # Use questionary for the actual selection. The choices are the
    # tool names plus a "Quit" sentinel.
    choices = [t.name for t in TOOLS] + ["Quit"]
    pick = questionary.select(
        "Pick a tool:",
        choices=choices,
        qmark="›",
    ).ask()
    if pick is None or pick == "Quit":
        return None
    return next(t for t in TOOLS if t.name == pick)


def show_tool_intro(console: Console, tool: Tool) -> None:
    """Print the tool's description + lab URL before we prompt for args."""
    content = Text.assemble(tool.description)
    if tool.lab_url:
        content.append("\n\nTarget lab: ")
        content.append(tool.lab_url, style="url")
    console.print(Panel(content, title=tool.name, border_style="primary",
                        padding=(1, 2)))


def collect_args(tool: Tool, q_style: QStyle) -> dict[str, str] | None:
    """
    Walk through the tool's prompts and collect the user's answers.

    Returns a dict {arg_name: value} ready to convert into a CLI
    command. Returns None if the user cancelled (Ctrl-C).
    """
    answers: dict[str, str] = {}
    for p in tool.prompts:
        if p.kind == "select":
            val = questionary.select(
                p.question,
                choices=p.choices,
                default=p.default,
                qmark="›",
                style=q_style,
            ).ask()
        elif p.kind == "path":
            # questionary.path gives tab-completion of file paths.
            val = questionary.path(
                p.question,
                default=p.default or "",
                qmark="›",
                style=q_style,
            ).ask()
        else:
            val = questionary.text(
                p.question,
                default=p.default or "",
                qmark="›",
                style=q_style,
                # Loose validation: require non-empty for required prompts.
                validate=(lambda v: bool(v.strip()) or "required") if p.required else None,
            ).ask()
        if val is None:
            return None  # user pressed Ctrl-C
        # Skip optional prompts the user left blank.
        if not val and not p.required:
            continue
        answers[p.arg] = val.strip()

    # Final "extra args" prompt for power users. Accept any extra flags
    # they want to tack on - --proxy, --verbose, --workers, etc.
    extra = questionary.text(
        "Extra args (optional, e.g. '--proxy burp --workers 5'):",
        default="",
        qmark="›",
        style=q_style,
    ).ask()
    if extra:
        answers["__extra"] = extra.strip()
    return answers


def check_paths(tool: Tool, answers: dict[str, str]) -> list[tuple[Prompt, Path]]:
    """
    For every Prompt with kind=="path" that the user filled in, verify
    the file actually exists. Returns a list of (prompt, path) pairs
    for the missing ones - empty list means everything checked out.

    Done before subprocess so the user gets a clear "file not found:
    examples/login.txt" message instead of a tool-side traceback
    when the script tries to read the missing file.
    """
    missing: list[tuple[Prompt, Path]] = []
    for p in tool.prompts:
        if p.kind != "path":
            continue
        if p.arg not in answers:
            continue
        path = Path(answers[p.arg])
        if not path.exists():
            missing.append((p, path))
    return missing


def build_command(tool: Tool, answers: dict[str, str]) -> list[str]:
    """
    Turn the prompt answers into a subprocess-ready argv list.

    Order: python3 SCRIPT then positional args in tool.prompts order,
    then flags, then any extra raw args. shlex handles any tricky
    quoting in the extra string.
    """
    cmd = [sys.executable, tool.script]

    # Positional args first, in declaration order.
    for p in tool.prompts:
        if p.arg.startswith("-"):
            continue
        if p.arg in answers:
            cmd.append(answers[p.arg])

    # Then flag args.
    for p in tool.prompts:
        if not p.arg.startswith("-"):
            continue
        if p.arg in answers:
            cmd.extend([p.arg, answers[p.arg]])

    # Finally any free-form extras the user typed.
    extra = answers.get("__extra")
    if extra:
        cmd.extend(shlex.split(extra))

    return cmd


def confirm_and_run(console: Console, cmd: list[str], q_style: QStyle) -> int:
    """
    Show the assembled command, ask the user to confirm, then exec it.

    Showing the command is intentional: it teaches the user exactly
    what shell command they would have typed to run this tool directly.
    Next time they don't need the launcher unless they want to.
    """
    # shlex.join quotes each arg so the displayed line is paste-safe.
    rendered = shlex.join(cmd)

    console.print()
    console.print(Panel(
        Text(rendered, style="success"),
        title="Will run",
        subtitle="(paste into your shell to skip the launcher next time)",
        border_style="accent",
        padding=(0, 2),
    ))

    go = questionary.confirm("Run it now?", default=True, qmark="›", style=q_style).ask()
    if not go:
        return -1

    console.print()
    # subprocess.run with no `capture_output` lets the tool's stdout/stderr
    # stream live to the user's terminal - including our color tags.
    result = subprocess.run(cmd)
    return result.returncode


# ---------------------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------------------
def main():
    # We need SOME theme loaded from the start because the banner and
    # the theme-picker prompt themselves use style names like [primary]
    # and [warning] that only resolve once a theme is active. Default
    # to "neon" for the pre-pick UI; the user can switch in the picker.
    console = make_console("neon")
    show_banner(console)

    if not show_disclaimer_acceptance(console):
        console.print("[error]Declined. Exiting.[/error]")
        sys.exit(0)

    theme_name = pick_theme(console)

    # Rebuild the console under the chosen theme (no-op if they picked
    # neon, since it's already loaded) and re-render the banner so the
    # user sees the theme transition take effect.
    if theme_name != "neon":
        console = make_console(theme_name)
        console.clear()
        show_banner(console)
    q_style = make_questionary_style(theme_name)

    while True:
        tool = show_tool_menu(console)
        if tool is None:
            console.print("[muted]bye[/muted]")
            break

        show_tool_intro(console, tool)

        # Sanity check: does the script we're about to invoke even exist?
        script_path = Path(__file__).parent / tool.script
        if not script_path.exists():
            console.print(f"[error]script not found: {script_path}[/error]")
            continue

        answers = collect_args(tool, q_style)
        if answers is None:
            console.print("[muted]cancelled[/muted]")
            continue

        # Validate that every path-kind prompt actually points at an
        # existing file. Catching this before exec gives a clear error
        # message instead of a tool-side FileNotFoundError traceback.
        missing = check_paths(tool, answers)
        if missing:
            for prompt, path in missing:
                console.print(f"[error]file not found:[/error] {path}  "
                              f"[muted](for '{prompt.question}')[/muted]")
            if any(p.arg == "request_file" for p, _ in missing):
                console.print("[muted]hint: see the examples/ directory for "
                              "starter templates you can edit.[/muted]")
            continue

        cmd = build_command(tool, answers)
        # build_command uses tool.script as-is; we need the absolute path
        # to be safe regardless of cwd.
        cmd[1] = str(script_path)

        rc = confirm_and_run(console, cmd, q_style)
        if rc == -1:
            console.print("[muted]skipped[/muted]")
        elif rc == 0:
            console.print("[success]tool exited successfully[/success]")
        else:
            console.print(f"[error]tool exited with code {rc}[/error]")

        # Ask whether to loop back to the menu or quit.
        again = questionary.confirm(
            "Back to menu?",
            default=True,
            qmark="›",
            style=q_style,
        ).ask()
        if not again:
            console.print("[muted]bye[/muted]")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl-C at any prompt - exit cleanly without a traceback.
        print()
        print("interrupted")
        sys.exit(130)
