"""Main-content extraction for scraped reference pages (untrusted HTML).

trafilatura removes navigation and other boilerplate. When it returns almost nothing (it
can over-prune pages that are not articles), a fallback is used: the ``<pre>`` blocks of a
mailing-list archive, else the whole-page text. Two stricter checks were tried on the
2026-10-26 pages and dropped: "kept under 25% of the page" and "dropped the page's own CVE
ID" fired on 40% of pages where trafilatura had correctly kept the advisory and dropped
navigation or a header (each row already records its CVE). Pages that are only a
no content for a client that doesn't run JavaScript or log in (application shells,
redirect stubs, bot checks, login walls) are flagged ``js_shell`` instead. PDFs are not
extracted. Short pages that are out of the corpus for no other reason are flagged
``too_short``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cti.references.text import html_to_text

MAX_HTML_BYTES = 2 * 1024 * 1024  # the scraper's body cap; never parse more than this
MIN_CHARS = 200  # less than this is not a usable page
SHELL_MAX_CHARS = 600
# Phrases a JavaScript shell or bot check shows instead of content (only on short pages).
_SHELL_PHRASES = re.compile(
    r"enable javascript|javascript is (?:required|disabled)|javascript must be enabled"
    r"|validating human|checking your browser|verify you are human|^\s*loading(?:\.\.\.|…)?\s*$"
    r"|please wait while|sign in to continue",
    re.IGNORECASE | re.MULTILINE,
)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass(frozen=True)
class Cleaned:
    text: str
    method: str  # trafilatura | pre | full | plain | none
    flags: tuple[str, ...] = ()
    full_chars: int = 0


def is_js_shell(full_text: str) -> bool:
    if len(full_text) < MIN_CHARS:
        return True
    return len(full_text) < SHELL_MAX_CHARS and bool(_SHELL_PHRASES.search(full_text))


def _pre_text(html: str) -> str:
    """Text of all <pre> blocks: mailing-list archives keep the message there."""
    import lxml.html

    parser = lxml.html.HTMLParser(no_network=True, remove_comments=True)
    try:
        # bytes, not str: lxml rejects str input that carries an XML encoding declaration
        root = lxml.html.fromstring(html.encode("utf-8"), parser=parser)
    except (ValueError, lxml.etree.ParserError):
        return ""
    return "\n\n".join(p.text_content().strip() for p in root.iter("pre")).strip()


def _trafilatura(html: str) -> str:
    import trafilatura

    return (
        trafilatura.extract(
            html,
            output_format="txt",
            include_tables=True,
            include_comments=False,
            include_links=False,  # keeps live IOC URLs out of the text; NER defangs later
            include_images=False,
            deduplicate=False,  # its cache is process-global, which breaks determinism
            favor_recall=True,
            with_metadata=False,
        )
        or ""
    ).strip()


def clean(body: bytes, content_type: str, *, mailing_list: bool = False) -> Cleaned:
    if content_type == "application/pdf":
        return Cleaned("", "none", ("pdf_skipped",))
    decoded = body[:MAX_HTML_BYTES].decode("utf-8", errors="replace")
    if content_type == "text/plain":
        return Cleaned(decoded.strip(), "plain", (), len(decoded.strip()))

    full = html_to_text(decoded)
    if is_js_shell(full):
        return Cleaned("", "none", ("js_shell",), len(full))
    text = _trafilatura(decoded)
    if len(text) >= MIN_CHARS:
        return Cleaned(text, "trafilatura", (), len(full))
    if mailing_list and len(pre := _pre_text(decoded)) >= MIN_CHARS:
        return Cleaned(pre, "pre", (), len(full))
    return Cleaned(full, "full", ("extraction_fallback",), len(full))


def with_length_flag(cleaned: Cleaned) -> Cleaned:
    """Flag text too short for the corpus that no other flag explains."""
    if len(cleaned.text) >= MIN_CHARS or "js_shell" in cleaned.flags or cleaned.method == "none":
        return cleaned
    return Cleaned(cleaned.text, cleaned.method, (*cleaned.flags, "too_short"), cleaned.full_chars)
