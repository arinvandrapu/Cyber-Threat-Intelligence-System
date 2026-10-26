import base64
import hashlib
import json

import pytest

from cti.cli import main
from cti.enrich.cleaner import MIN_CHARS, clean, is_js_shell, with_length_flag
from cti.enrich.references import build
from cti.snapshot import Snapshot
from cti.storage import LocalStorage

from .conftest import gzip_bytes, jsonl

ADVISORY = (
    "A heap overflow in the widget parser lets a remote attacker execute code by sending "
    "a crafted request. Affected versions are 1.0 through 1.4; upgrade to 1.5. "
)
NAV = "".join(f'<li><a href="/p{i}">Product {i}</a></li>' for i in range(60))

ARTICLE = f"""<html><head><title>CVE-2026-1234 advisory</title><script>var x=1;</script></head>
<body><header><nav><ul>{NAV}</ul></nav></header>
<main><article><h1>Widget heap overflow (CVE-2026-1234)</h1>
<p>{ADVISORY * 3}</p>
<pre>curl -X POST https://target.example/api --data @payload.bin</pre>
<table><tr><th>Version</th><th>Fixed</th></tr><tr><td>1.4</td><td>1.5</td></tr></table>
</article></main>
<footer><ul>{NAV}</ul><p>Copyright Example Corp. Privacy. Terms. Cookies.</p></footer>
</body></html>""".encode()

MSRC_SHELL = b"""<html><head><title>Security Update Guide - Microsoft Security Response Center
</title></head><body><div id="root"></div><noscript>You need to enable JavaScript.</noscript>
</body></html>"""

HUNTR_SHELL = (
    b"<html><body><h1>huntr - The world's first bug bounty platform for AI/ML</h1>"
    b"<p>Loading...</p><footer>" + b"Supported by an example sponsor. " * 8 + b"</footer>"
    b"</body></html>"
)

MAILING_LIST = f"""<html><body><table>{NAV}</table>
<pre>Subject: CVE-2026-1234: widget heap overflow
{ADVISORY * 3}
</pre></body></html>""".encode()


def test_article_boilerplate_removed_and_content_kept():
    result = clean(ARTICLE, "text/html")
    assert result.method == "trafilatura"
    assert "heap overflow" in result.text
    assert "curl -X POST" in result.text  # code block kept
    assert "Product 7" not in result.text  # navigation removed
    assert "Copyright" not in result.text
    assert "var x" not in result.text
    assert "https://target.example" in result.text  # body text kept verbatim; links not added
    assert result.full_chars > len(result.text)


@pytest.mark.parametrize("page", [MSRC_SHELL, HUNTR_SHELL])
def test_javascript_shells_are_flagged(page):
    result = clean(page, "text/html")
    assert result.flags == ("js_shell",)
    assert result.text == ""


def test_short_real_text_is_not_a_shell():
    terse = "CVE-2026-1234: improper loading of plugins in Widget 1.4 allows code execution. " * 3
    assert MIN_CHARS <= len(terse) < 600
    assert not is_js_shell(terse)  # "loading" only counts as a whole line
    assert not is_js_shell("A" * 700 + "\nLoading...")  # long pages never count as shells
    assert is_js_shell("Advisory\nLoading...\n" + "Footer text. " * 20)


def test_mailing_list_message_survives():
    result = clean(MAILING_LIST, "text/html", mailing_list=True)
    assert "widget heap overflow" in result.text
    assert result.method in ("trafilatura", "pre")


def test_fallback_when_extraction_is_near_empty(monkeypatch):
    monkeypatch.setattr("cti.enrich.cleaner._trafilatura", lambda html: "")
    result = clean(ARTICLE, "text/html")
    assert result.method == "full" and result.flags == ("extraction_fallback",)
    assert "heap overflow" in result.text
    result = clean(MAILING_LIST, "text/html", mailing_list=True)
    assert result.method == "pre" and "Product 7" not in result.text


def test_plain_text_is_not_stripped_of_angle_brackets():
    body = b"From: Exim <security@exim.example>\nHeap overflow in <smtp> handling.\n"
    result = clean(body, "text/plain")
    assert result.method == "plain"
    assert "<security@exim.example>" in result.text and "<smtp>" in result.text


def test_pdfs_are_skipped():
    result = clean(b"%PDF-1.7 ...", "application/pdf")
    assert (result.method, result.flags, result.text) == ("none", ("pdf_skipped",), "")


def test_input_is_capped(monkeypatch):
    seen = []
    monkeypatch.setattr("cti.enrich.cleaner.MAX_HTML_BYTES", 100)
    monkeypatch.setattr("cti.enrich.cleaner.html_to_text", lambda html: seen.append(html) or "")
    assert clean(ARTICLE, "text/html").flags == ("js_shell",)
    assert len(seen[0]) <= 100


def page(url, body, content_type="text/html", cve="CVE-2026-1234"):
    return {
        "cve": cve,
        "url": url,
        "final_url": url,
        "ref_type": "vendor_advisory",
        "content_type": content_type,
        "status": 200,
        "truncated": False,
        "body_b64": base64.b64encode(body).decode(),
    }


def test_build_rows_and_summary(tmp_path):
    snap = Snapshot.create(LocalStorage(tmp_path), "2026-10-26")
    records = [
        page("https://vendor.example/advisory/1", ARTICLE),
        page("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1234", MSRC_SHELL),
        page("https://www.exploit-db.com/exploits/1", ARTICLE),
        page("https://vendor.example/a.pdf", b"%PDF", "application/pdf"),
        {"cve": "CVE-2026-1234", "url": "https://blocked.example/", "skipped": "robots"},
    ]
    snap.write_raw("references", "pages-0001.jsonl.gz", gzip_bytes(jsonl(records)))
    snap.mark_complete("references")
    rows, summary = build(snap)
    assert len(rows) == 4  # the robots-skipped page has no body
    assert rows == sorted(rows, key=lambda r: r["id"])
    by_url = {r["url"]: r for r in rows}
    article = by_url["https://vendor.example/advisory/1"]
    assert article["in_corpus"] and article["cve_ids"] == ["CVE-2026-1234"]
    assert by_url["https://www.exploit-db.com/exploits/1"]["ref_type"] == "exploit"  # reclassified
    assert summary["in_corpus"] == 2
    assert summary["flags"] == {"js_shell": 1, "pdf_skipped": 1}
    assert summary["js_shell_hosts"] == {"msrc.microsoft.com": 1}


def test_xhtml_pre_fallback(monkeypatch):
    monkeypatch.setattr("cti.enrich.cleaner._trafilatura", lambda html: "")
    xhtml = b'<?xml version="1.0" encoding="utf-8"?>\n' + MAILING_LIST
    result = clean(xhtml, "text/html", mailing_list=True)
    assert result.method == "pre" and "widget heap overflow" in result.text


def test_odd_bodies_do_not_crash():
    for body in (b"", b"\xff\xfe\x00garbage\x00", "<p>café</p>".encode("latin-1")):
        result = clean(body, "text/html")
        assert result.flags == ("js_shell",)  # nothing usable
    assert with_length_flag(clean(b"short note", "text/plain")).flags == ("too_short",)
    assert with_length_flag(clean(MSRC_SHELL, "text/html")).flags == ("js_shell",)


def make_snapshot(tmp_path, complete=True):
    snap = Snapshot.create(LocalStorage(tmp_path / "snapshots"), "2026-10-26")
    records = [page("https://vendor.example/advisory/1", ARTICLE)]
    snap.write_raw("references", "pages-0001.jsonl.gz", gzip_bytes(jsonl(records)))
    if complete:
        snap.mark_complete("references")
    return snap


def test_incomplete_scrape_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not complete"):
        build(make_snapshot(tmp_path, complete=False))


def test_build_is_deterministic(tmp_path):
    snap = make_snapshot(tmp_path)
    assert build(snap) == build(snap)


def test_cli_references(tmp_path, monkeypatch, capsys):
    make_snapshot(tmp_path)
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    assert main(["enrich", "--date", "2026-10-26", "--only", "references"]) == 0
    out = tmp_path / "enriched" / "2026-10-26"
    summary = json.loads((out / "references-summary.json").read_text())
    digest = hashlib.sha256((out / "references.jsonl.gz").read_bytes()).hexdigest()
    assert summary["references_sha256"] == digest and summary["in_corpus"] == 1


def test_cli_explains_missing_enrich_extra(tmp_path, monkeypatch, capsys):
    make_snapshot(tmp_path)
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    assert main(["enrich", "--date", "2026-10-26"]) == 2
    assert "needs the enrich extra" in capsys.readouterr().err
    assert not (tmp_path / "enriched").exists()  # fails before writing anything
