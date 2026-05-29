"""
_truncate.py
============
Strip non-essential markup from HTML responses so we can ship the
condensed "signal" of a page to an LLM context, a JSON log, or just
a smaller --output file.

WHY THIS MATTERS
----------------
Raw web responses are 90% noise from a pentest perspective:
  - <script>...</script> tagged libraries (jQuery, React bundles)
    that are megabytes long and tell us nothing about the app's
    server-side surface.
  - <style>...</style> blocks and external CSS
  - <svg> illustrations + base64-encoded inline images
  - <noscript>, tracking pixels, ad iframes
  - Boilerplate HTML structure that's the same across every page

The 10% we ACTUALLY want:
  - <form> tags, their action/method, every <input> name
  - Visible text near forms (labels, error messages)
  - <a href> URLs in the body (for crawling / link discovery)
  - <meta> tags (CSP fragments, X-Frame info in <meta>)
  - Hidden tokens (CSRF, anti-forgery)

For LLM-driven exploitation (the user's "Dynamic Context-Window
Truncation" requirement) shipping the raw 200 KB of a React app's
hydrated HTML costs token budget AND obscures the signal. After
stripping noise + collapsing whitespace, the same page often fits
in 2-5 KB and the model has exactly the structural info it needs
to reason about attack surface.

WHY REGEX AND NOT BEAUTIFULSOUP?
--------------------------------
Famously, "you can't parse HTML with regex." For full-fidelity DOM
manipulation that's true. But for "drop these specific tags + their
contents" the regex approach is good enough for pentest tooling AND
avoids adding bs4/lxml as a dependency just for this one module.
The script's only hard dep is `requests`.

The patterns below assume HTML5-ish input with no
particularly-pathological nested CDATA / comments-inside-strings,
which is fine for the responses real web apps serve.

TRADE-OFF: edge cases where a `<script>` tag appears INSIDE a
string literal in JS will get truncated too aggressively. For a
pentest "see the structure" use case, that's acceptable.
"""

import re


# Multi-line / case-insensitive flags shared by every pattern.
_FLAGS = re.DOTALL | re.IGNORECASE

# Patterns we use to strip noise. Listed in apply order.
_NOISE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # HTML comments. Often hold dev notes or templating leftovers.
    (re.compile(r"<!--.*?-->", _FLAGS), ""),
    # script + style + svg + canvas: drop the ENTIRE block including
    # the contents (the .*? matches lazily up to the closing tag).
    (re.compile(r"<script\b[^>]*>.*?</script\s*>", _FLAGS), ""),
    (re.compile(r"<style\b[^>]*>.*?</style\s*>", _FLAGS), ""),
    (re.compile(r"<svg\b[^>]*>.*?</svg\s*>", _FLAGS), ""),
    (re.compile(r"<canvas\b[^>]*>.*?</canvas\s*>", _FLAGS), ""),
    (re.compile(r"<noscript\b[^>]*>.*?</noscript\s*>", _FLAGS), ""),
    # Self-closing media tags: drop the tag itself (no inner contents).
    (re.compile(r"<img\b[^>]*/?>", _FLAGS), ""),
    (re.compile(r"<iframe\b[^>]*>.*?</iframe\s*>", _FLAGS), ""),
    (re.compile(r"<video\b[^>]*>.*?</video\s*>", _FLAGS), ""),
    (re.compile(r"<audio\b[^>]*>.*?</audio\s*>", _FLAGS), ""),
    (re.compile(r"<source\b[^>]*/?>", _FLAGS), ""),
    (re.compile(r"<picture\b[^>]*>.*?</picture\s*>", _FLAGS), ""),
    # `<link rel="stylesheet" ...>` references external CSS. Useless
    # for us. Some <link> tags are useful (preload hints reveal asset
    # names), but the cost of preserving them isn't worth the noise.
    (re.compile(r"<link\b[^>]*/?>", _FLAGS), ""),
]

# Collapse runs of whitespace to single spaces. Applied at the end so
# the structural strip happens first. We DON'T strip whitespace inside
# preserved <pre> blocks - those carry semantic indentation - but a
# basic global collapse is fine for our use case.
_WHITESPACE_RE = re.compile(r"[ \t\f\v]+")
_BLANKLINES_RE = re.compile(r"\n\s*\n+")


def strip_html_noise(html: str) -> str:
    """
    Remove scripts, styles, SVG, images, iframes, comments, and
    similar noise from an HTML string. Returns a smaller string with
    the structural / form / link content preserved.

    Input is treated case-insensitively and we accept both
    properly-closed and self-closing tags where applicable.
    """
    out = html
    for pattern, replacement in _NOISE_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def collapse_whitespace(text: str) -> str:
    """
    Normalize whitespace: runs of spaces/tabs collapse to one space;
    runs of blank lines collapse to one blank line. Preserves single
    newlines so the structure is still scannable.
    """
    text = _WHITESPACE_RE.sub(" ", text)
    text = _BLANKLINES_RE.sub("\n\n", text)
    return text


def truncate(text: str, max_chars: int) -> str:
    """
    Hard char-cap with a `[truncated]` marker. 0 / negative means no
    cap (return input unchanged).
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n...[truncated, original was {len(text)} chars]"


def compact_response(body: str, max_chars: int = 5000) -> str:
    """
    Full pipeline: strip noise -> collapse whitespace -> truncate.
    The default 5000-char cap is a sane LLM-context-friendly size.
    """
    stripped = strip_html_noise(body)
    compact = collapse_whitespace(stripped)
    return truncate(compact, max_chars)
