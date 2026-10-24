import base64
import json

import httpx
import pytest
import respx

from cti.http.safe_fetch import SafeFetcher
from cti.references.classifier import RefType, classify_url
from cti.references.scraper import HostThrottle, RobotsCache, scrape, scrape_one
from cti.references.selection import Target, pick_references, rank_cves, select_targets
from cti.references.text import html_to_text

PUBLIC = "93.184.216.34"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/o/r/security/advisories/GHSA-abcd-1234", RefType.GITHUB_ADVISORY),
        ("https://github.com/o/r/commit/abc", RefType.GITHUB_COMMIT),
        ("https://github.com/o/r/pull/9", RefType.GITHUB_ISSUE),
        ("https://github.com/o/r", RefType.GITHUB_REPO),
        ("https://gist.github.com/x/1", RefType.CODE),
        ("https://www.youtube.com/watch?v=1", RefType.MEDIA),
        ("https://seclists.org/fulldisclosure/2026/Jan/1", RefType.MAILING_LIST),
        ("https://lists.debian.org/x", RefType.MAILING_LIST),
        ("https://www.cisa.gov/news/x", RefType.GOVERNMENT),
        ("https://www.ncsc.gov.uk/x", RefType.GOVERNMENT),
        ("https://access.redhat.com/errata/x", RefType.VENDOR_ADVISORY),
        ("https://WWW.Debian.org/security/x", RefType.VENDOR_ADVISORY),
        ("https://vendor.example/security-advisory/1", RefType.VENDOR_ADVISORY),
        ("https://vendor.example/patch/1", RefType.PATCH),
        ("https://blog.example/post", RefType.ARTICLE),
        ("https://nvd.nist.gov/vuln/detail/CVE-2026-1", RefType.UNKNOWN),
        ("ftp://example.com/x", RefType.UNKNOWN),
        ("not a url", RefType.UNKNOWN),
    ],
)
def test_classify_url(url, expected):
    assert classify_url(url) == expected


def test_rank_puts_kev_first_newest_first_then_epss():
    ranked = rank_cves(
        ["A", "B", "C", "D"],
        kev_added={"C": "2026-01-01", "D": "2026-06-01", "Z": "2026-09-09"},
        epss={"A": 0.1, "B": 0.9},
    )
    assert ranked == ["D", "C", "B", "A"]  # Z is outside the window


def test_pick_references_prefers_advisories_one_per_host():
    urls = [
        "https://blog.example/a",
        "https://access.redhat.com/1",
        "https://access.redhat.com/2",
        "https://github.com/o/r/commit/1",
        "https://www.youtube.com/watch?v=1",
        "https://gov.example.gov/x",
    ]
    picked = pick_references(urls, per_cve=3)
    assert [u for u, _ in picked] == [
        "https://access.redhat.com/1",
        "https://gov.example.gov/x",
        "https://blog.example/a",
    ]


def test_select_targets_caps_total_and_dedupes_urls():
    refs = {
        "CVE-1": ["https://a.example/advisory/1", "https://b.example/x"],
        "CVE-2": ["https://a.example/advisory/1", "https://c.example/y"],
    }
    targets = select_targets(refs, {}, {"CVE-1": 0.9, "CVE-2": 0.1}, per_cve=2, max_pages=3)
    assert [t.url for t in targets] == [
        "https://a.example/advisory/1",
        "https://b.example/x",
        "https://c.example/y",
    ]


def test_html_to_text_drops_scripts_and_keeps_blocks():
    html = (
        "<html><head><title>t</title><script>evil()</script></head><body><h1>Title</h1>"
        "<p>First &amp; para.</p><style>x{}</style><p>Second</p></body></html>"
    )
    assert html_to_text(html) == "t\nTitle\n\nFirst & para.\n\nSecond"  # <title> kept


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def test_host_throttle_spaces_same_host_only():
    clock = FakeClock()
    throttle = HostThrottle(2.0, clock=clock, sleep=clock.sleep)
    throttle.wait("https://a.example/1")
    throttle.wait("https://b.example/1")
    throttle.wait("https://a.example/2")
    assert clock.sleeps == [2.0]


@pytest.fixture
def fetcher():
    with SafeFetcher(
        "cti-pipeline/0.1 (+mailto:t@example.com)", resolver=lambda host, port: [PUBLIC]
    ) as f:
        yield f


def no_wait():
    return HostThrottle(0.0)


@respx.mock
@pytest.mark.parametrize(
    ("robots_response", "allowed"),
    [
        (httpx.Response(200, text="User-agent: *\nDisallow: /private/"), False),
        (httpx.Response(200, text="User-agent: cti-pipeline\nDisallow: /\n"), False),
        (httpx.Response(200, text="User-agent: *\nAllow: /\n"), True),
        (httpx.Response(404), True),  # RFC 9309: unavailable -> no restrictions
        (httpx.Response(503), False),  # RFC 9309: unreachable -> assume disallowed
    ],
)
def test_robots_semantics(fetcher, robots_response, allowed):
    respx.get(f"https://{PUBLIC}/robots.txt").mock(return_value=robots_response)
    assert RobotsCache(fetcher).allowed("https://site.example/private/page") is allowed


@respx.mock
def test_scrape_one_records_body_and_skips(fetcher):
    respx.get(f"https://{PUBLIC}/robots.txt").mock(
        return_value=httpx.Response(200, text="User-agent: *\nDisallow: /secret\n")
    )
    respx.get(f"https://{PUBLIC}/advisory").mock(
        return_value=httpx.Response(200, text="<p>hi</p>", headers={"content-type": "text/html"})
    )
    respx.get(f"https://{PUBLIC}/video").mock(
        return_value=httpx.Response(200, content=b"\x00", headers={"content-type": "video/mp4"})
    )
    robots = RobotsCache(fetcher)
    ok = scrape_one(
        Target("CVE-1", "https://site.example/advisory", RefType.ARTICLE),
        fetcher,
        robots,
        no_wait(),
    )
    assert base64.b64decode(ok["body_b64"]) == b"<p>hi</p>"
    assert ok["status"] == 200 and ok["content_type"] == "text/html"
    blocked = scrape_one(
        Target("CVE-1", "https://site.example/secret", RefType.ARTICLE), fetcher, robots, no_wait()
    )
    assert blocked["skipped"] == "robots" and "body_b64" not in blocked
    video = scrape_one(
        Target("CVE-1", "https://site.example/video", RefType.ARTICLE), fetcher, robots, no_wait()
    )
    assert "body_b64" not in video  # unsupported content types are not stored


def test_scrape_records_ssrf_block_without_failing():
    with SafeFetcher("ua", resolver=lambda h, p: ["169.254.169.254"]) as f:
        [record] = list(
            scrape(
                [Target("CVE-1", "http://evil.example/", RefType.ARTICLE)],
                f,
                workers=2,
                host_interval=0.0,
            )
        )
    assert record["skipped"].startswith("blocked")


def test_references_source_end_to_end(snapshot, settings, monkeypatch):
    """Selection reads NVD/KEV/EPSS from the snapshot; pages are stored and parsed back."""
    from cti.models import CveSignal, Document
    from cti.sources import references as refmod
    from cti.sources.base import FetchContext

    with pytest.raises(RuntimeError, match="needs completed sources"):
        refmod.ReferencesSource(settings).targets(snapshot)

    for name in ("nvd", "kev", "epss"):
        snapshot.mark_complete(name)
    nvd_doc = Document(
        id="nvd:CVE-1",
        source="nvd",
        source_id="CVE-1",
        title="CVE-1",
        metadata={"references": ["https://site.example/advisory"]},
    )
    monkeypatch.setattr(refmod.NVDSource, "parse", lambda self, s: iter([nvd_doc]))
    monkeypatch.setattr(refmod.KEVSource, "parse", lambda self, s: iter([]))
    monkeypatch.setattr(
        refmod.EPSSSource,
        "parse",
        lambda self, s: iter(
            [CveSignal(cve="CVE-1", source="epss", as_of="snapshot", values={"epss": 0.5})]
        ),
    )

    def fake_scrape(targets, fetcher, **kw):
        for t in targets:
            yield {
                "cve": t.cve,
                "url": t.url,
                "ref_type": str(t.ref_type),
                "status": 200,
                "content_type": "text/html",
                "body_b64": base64.b64encode(b"<p>Patch now</p>").decode(),
            }

    monkeypatch.setattr(refmod, "scrape", fake_scrape)
    with httpx.Client() as client:
        ctx = FetchContext(
            snapshot=snapshot, client=client, settings=settings, snapshot_date=snapshot.date
        )
        refmod.ReferencesSource(settings).fetch(ctx)
    names = [e.name for e in snapshot.entries("references")]
    assert names == ["targets.json.gz", "pages-0001.jsonl.gz"]
    [doc] = refmod.ReferencesSource(settings).parse(snapshot)
    assert doc.text == "Patch now" and doc.cves == ("CVE-1",)
    targets = json.loads(
        __import__("gzip").decompress(snapshot.read_raw(snapshot.entries("references")[0]))
    )
    assert targets[0]["url"] == "https://site.example/advisory"


def test_pick_references_one_per_host_with_query_and_userinfo():
    picked = pick_references(
        ["https://a.example?x=1", "https://a.example/y", "https://u@a.example/z"], per_cve=3
    )
    assert len(picked) == 1


def test_html_to_text_without_closing_head():
    assert html_to_text("<html><head><title>t</title><body><p>Real text</p>") == "t\nReal text"


@pytest.mark.parametrize(
    "url",
    [
        "https://" + "a" * 70 + ".example/x",  # label > 63 chars
        "https://a..b/x",
        "https://xn--a.com/x",
    ],
)
@respx.mock  # no request may leave the machine: these must fail before any connection
def test_malformed_hosts_never_abort_the_scrape(url):
    from cti.http.safe_fetch import system_resolver  # real IDNA errors come from here

    with SafeFetcher("ua", resolver=system_resolver) as f:
        records = list(
            scrape([Target("CVE-1", url, RefType.ARTICLE)], f, workers=1, host_interval=0.0)
        )
    assert len(records) == 1
    assert "skipped" in records[0] or "error" in records[0]


@respx.mock
def test_robots_wildcards_and_longest_match(fetcher):
    respx.get(f"https://{PUBLIC}/robots.txt").mock(
        return_value=httpx.Response(
            200, text="User-agent: *\nDisallow: /*.php\nDisallow: /a\nAllow: /a/b\n"
        )
    )
    robots = RobotsCache(fetcher)
    assert not robots.allowed("https://site.example/index.php")
    assert robots.allowed("https://site.example/a/b")
    assert not robots.allowed("https://site.example/a/c")


@respx.mock
def test_redirect_target_robots_checked():
    ips = {"site.example": ["93.184.216.34"], "other.example": ["151.101.1.69"]}
    with SafeFetcher("ua", resolver=lambda h, p: ips[h]) as f:
        respx.get("https://93.184.216.34/robots.txt").mock(return_value=httpx.Response(404))
        respx.get("https://151.101.1.69/robots.txt").mock(
            return_value=httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        )
        respx.get("https://93.184.216.34/go").mock(
            return_value=httpx.Response(302, headers={"location": "https://other.example/page"})
        )
        respx.get("https://151.101.1.69/page").mock(return_value=httpx.Response(200, text="x"))
        record = scrape_one(
            Target("CVE-1", "https://site.example/go", RefType.ARTICLE),
            f,
            RobotsCache(f),
            no_wait(),
        )
    assert record["skipped"] == "robots (redirect target)"
    assert "body_b64" not in record


@respx.mock
def test_cached_robots_means_one_throttle_wait_per_page(fetcher):
    respx.get(f"https://{PUBLIC}/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(url__regex=rf"https://{PUBLIC}/p\d").mock(return_value=httpx.Response(200))
    clock = FakeClock()
    throttle = HostThrottle(2.0, clock=clock, sleep=clock.sleep)
    robots = RobotsCache(fetcher)
    for i in range(3):
        scrape_one(
            Target("CVE-1", f"https://site.example/p{i}", RefType.ARTICLE),
            fetcher,
            robots,
            throttle,
        )
    # robots fetch + page 0, then pages 1 and 2: four bookings, 2 s apart
    assert clock.sleeps == [2.0, 2.0, 2.0]
