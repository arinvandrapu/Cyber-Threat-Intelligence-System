import pytest

from cti.defang import defang_host, defang_ip, defang_url, refang


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://evil.example.com/a.b/c", "hxxps://evil[.]example[.]com/a.b/c"),
        ("http://203.0.113.7:8080/x", "hxxp://203[.]0[.]113[.]7:8080/x"),
        ("HTTP://Evil.com", "hxxp://Evil[.]com"),
        ("evil.com/path", "evil[.]com/path"),
    ],
)
def test_defang_url(url, expected):
    assert defang_url(url) == expected
    assert refang(defang_url(url)).lower() == url.lower()


def test_defang_ip_and_host():
    assert defang_ip("203.0.113.7") == "203.0.113[.]7"
    assert defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"
    assert refang(defang_ip("2001:db8::1")) == "2001:db8::1"
    assert defang_host("a.b.c") == "a[.]b[.]c"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("evil(.)com", "evil.com"),
        ("evil{.}com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("evil(DOT)com", "evil.com"),
        ("hxxps[:]//evil[.]com", "https://evil.com"),
        ("see hXXp://a[.]b", "see http://a.b"),
        ("fxp://files[.]example", "ftp://files.example"),
        ("user[@]evil[.]com", "user@evil.com"),
        ("203.0.113[.]7", "203.0.113.7"),
    ],
)
def test_refang_in_text_forms(text, expected):
    assert refang(text) == expected


def test_defang_ioc_ip_port():
    from cti.sources.abusech import defang_ioc

    assert defang_ioc("203.0.113.7:443", "ip:port") == "203.0.113[.]7:443"
    # IPv6 with a port keeps brackets, so the port can't be read as part of the address
    assert defang_ioc("[2001:db8::1]:443", "ip:port") == "[2001[:]db8[:][:]1]:443"
