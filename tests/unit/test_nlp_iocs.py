import socket
import time
from itertools import pairwise

import pytest

from cti.defang import refang
from cti.nlp import iocs
from cti.nlp.iocs import extract, valid_cvss


def found(text: str, kind: str | None = None) -> list[str]:
    return [refang(i.value) for i in extract(text) if kind is None or i.type == kind]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C2 at 203.0.113.7.", ["203.0.113.7"]),
        ("beacon to 203.0.113[.]7:443", ["203.0.113.7"]),
        ("hosts 198.51.100(.)9 and 192.0.2{.}1", ["198.51.100.9", "192.0.2.1"]),
        ("Windows 10.0.19041.1 build", []),  # five parts: not an address
        ("version 1.2.3.4.5", []),
        ("01.2.3.4 and 1.2.3.256", []),  # leading zero, octet > 255
        ("version 10.0.0.1", []),
        ("prior to versions 8.1.2.1, 8.0.4.1, and 7.2.3.1", []),
        ("affected 7.3.0.0 through 7.3.0.10", []),
        ("all versions up to, and including, 5.5.1.3", []),
        ("OTP 28.4.2 and OTP 27.3.4.10", []),  # a three-part version nearby
        ("Netgear EX6200 1.0.3.94 is affected", []),  # product name right before
        ("IP 10.0.0.1 and route 192.168.1.100/32", ["10.0.0.1", "192.168.1.100"]),
        ("LHOST => 10.0.0.5", ["10.0.0.5"]),
        # defanged addresses are indicators even in a version-like list
        ("IOCs: 198.51.100[.]23 - 203.0.113[.]5", ["198.51.100.23", "203.0.113.5"]),
    ],
)
def test_ipv4(text, expected):
    assert found(text, "ipv4") == expected


def test_ipv4_public_flag_and_defang_at_rest():
    [pub, priv] = extract("from 8.8.8.8 to 10.0.0.1")
    assert (pub.value, pub.public) == ("8.8.8[.]8", True)
    assert priv.public is False
    assert not pub.defanged_in_source
    assert extract("x 8.8.8[.]8")[0].defanged_in_source


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("bind to 2001:db8::1 now", ["2001:db8::1"]),
        ("loopback ::1", ["::1"]),
        ("at 10:30:00 UTC", []),
        ("std::vector", []),
        ("mac 00:1a:2b:3c:4d:5e", []),
    ],
)
def test_ipv6(text, expected):
    assert found(text, "ipv6") == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C2 evil.example.com", ["evil.example.com"]),
        ("hosted on bad[.]top and c2(.)xyz", ["bad.top", "c2.xyz"]),
        ("plain c2-example.xyz", ["c2-example.xyz"]),  # newer TLD common in abuse.ch data
        ("app.example.co.uk", ["app.example.co.uk"]),
        ("see setup.py, README.md, build.sh", []),  # real TLDs used as file extensions
        ("ASP.NET and VB.NET", []),
        ("CloudTaskService.java and downloadDocEx.do", []),
        ("call subprocess.run or list.next", []),  # newer TLDs, not defanged
        ("obj.name() and os.open(x)", []),
        ("supported.You can", []),  # missing space after a full stop
        ("Netty 4.1.135.Final", []),
        ("rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org", []),
        ("mail admin@example.com", []),  # an address, not a host mention
        ("path /var/www/site.com", []),
    ],
)
def test_domains(text, expected):
    assert found(text, "domain") == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://example.com/a?b=1.", ["https://example.com/a?b=1"]),
        ("hxxps[:]//evil[.]com/x", ["https://evil.com/x"]),
        ("(http://example.org/path)", ["http://example.org/path"]),
        ("http://[2001:db8::1]:80/x", ["http://[2001:db8::1]:80/x"]),
        ("fxp://files[.]example.net/a", ["ftp://files.example.net/a"]),
        ("http://localhost/", []),  # no dot: not an indicator
    ],
)
def test_urls(text, expected):
    assert found(text, "url") == expected


def test_url_host_is_not_also_a_domain_or_ip():
    kinds = [i.type for i in extract("get http://203.0.113.7/a and http://evil.com/b")]
    assert kinds == ["url", "url"]


def test_hashes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    got = [(i.type, i.value) for i in extract(f"md5 {md5} sha1 {sha1.upper()} sha256 {sha256}")]
    assert got == [("md5", md5), ("sha1", sha1), ("sha256", sha256)]
    assert extract(f"{md5}ab") == []  # 34 hex chars: no partial match
    assert extract(f"commit {sha1}") == []
    assert extract(f"fixed before {sha1}") == []
    assert extract(f"actions/checkout@{sha1}") == []
    assert extract("9" * 64) == []  # a number, not a digest
    assert extract(f"https://github.com/x/y/commit/{sha1}")[0].type == "url"


def test_cve_ids():
    assert found("see cve-2024-12345 and CVE-2023-0001", "cve") == [
        "CVE-2024-12345",
        "CVE-2023-0001",
    ]
    assert found("XCVE-2024-1234 CVE-2024-123", "cve") == []


V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.mark.parametrize(
    ("vector", "ok"),
    [
        (V31, True),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", True),
        ("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N", True),  # v3: any order
        (V31 + "/E:P/RL:O/RC:C", True),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", False),  # A missing
        (V31 + "/AV:L", False),  # duplicate metric
        ("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", False),  # bad value
        (V40, True),
        (V40 + "/E:A/CR:H/U:Clear", True),
        ("CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", False),  # v4 order
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N", False),  # SA missing
        (V40 + "/U:clear", False),  # values are case-sensitive
        ("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", False),
    ],
)
def test_cvss_grammar(vector, ok):
    assert valid_cvss(vector) is ok


def test_cvss_version_is_never_a_score():
    text = f"Score: 9.8 (CRITICAL) Vector: {V31}"
    assert [(i.type, i.value) for i in extract(text)] == [("cvss", V31)]
    assert found("Vector: CVSS:3.1/AV:N/AC:L", "cvss") == []


def test_offsets_index_the_original_text():
    text = "IOCs: hxxps[:]//bad[.]site/x and 198.51.100[.]9 and evil(.)example.com."
    for ioc in extract(text):
        span = text[ioc.start : ioc.end]
        assert refang(ioc.value).lower() == refang(span).lower()


def test_spans_do_not_overlap():
    out = extract("http://1.2.3.4/x 1.2.3.4 CVE-2024-1234 https://nvd.nist.gov/vuln/CVE-2024-9")
    spans = sorted((i.start, i.end) for i in out)
    assert all(a[1] <= b[0] for a, b in pairwise(spans))


def test_public_suffix_list_is_never_fetched(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("network access")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    iocs._psl.cache_clear()
    try:
        assert found("evil.example.com", "domain") == ["evil.example.com"]
    finally:
        iocs._psl.cache_clear()


def test_hash_at_end_of_sentence():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert [i.value for i in extract(f"the md5 is {md5}.")] == [md5]


@pytest.mark.parametrize(
    "text",
    [
        "a[.]" * 30000,
        "ab(.)" * 30000,
        "a." * 50000,
        " ".join(f"10.0.{i // 250}.{i % 250}" for i in range(8000)),
    ],
)
def test_adversarial_input_stays_linear(text):
    # scraped pages are untrusted: no input shape may make extraction blow up
    start = time.perf_counter()
    extract(text)
    assert time.perf_counter() - start < 2.0
