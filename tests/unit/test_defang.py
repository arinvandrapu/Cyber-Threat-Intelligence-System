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
    assert defang_ip("2001:db8::1") == "[2001:db8::1]"
    assert defang_host("a.b.c") == "a[.]b[.]c"
