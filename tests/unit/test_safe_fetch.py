import socket

import httpx
import pytest
import respx

from cti.http.safe_fetch import BlockedURLError, SafeFetcher, is_public_ip

PUBLIC = "93.184.216.34"
PUBLIC_2 = "151.101.1.69"


def resolver_for(mapping):
    def resolve(host, port):
        if host in mapping:
            return mapping[host]
        # literal IPs (including decimal/octal forms) go through the real resolver
        return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]

    return resolve


@pytest.fixture
def fetcher():
    f = SafeFetcher(
        "test-agent",
        resolver=resolver_for(
            {
                "example.com": [PUBLIC],
                "cdn.example.net": [PUBLIC_2],
                "internal.example.com": ["10.0.0.5"],
                "metadata.example.com": ["169.254.169.254"],
                "mixed.example.com": [PUBLIC, "127.0.0.1"],
                "v6local.example.com": ["::1"],
                "mapped.example.com": ["::ffff:127.0.0.1"],
            }
        ),
        max_bytes=10,
    )
    yield f
    f.close()


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:10.0.0.1",
        "2002:7f00:1::",
        "fec0::1",
        "2001:db8::1",
        "not-an-ip",
    ],
)
def test_non_public_ips_rejected(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize("ip", [PUBLIC, "8.8.8.8", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/",
        "http://example.com:8080/",
        "http://user:pass@example.com/",
        "http://internal.example.com/",
        "http://metadata.example.com/latest/meta-data/",
        "http://mixed.example.com/",
        "http://v6local.example.com/",
        "http://mapped.example.com/",
        "http://127.0.0.1/",
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0177.0.0.1/",  # octal 127.0.0.1
        "http://[::1]/",
        "http://169.254.169.254/",
        "http://[::1",
        "http:///nohost",
    ],
)
def test_blocked_urls(fetcher, url):
    with pytest.raises(BlockedURLError):
        fetcher.validate(url)


@respx.mock
def test_connects_to_pinned_ip_with_host_header_and_sni(fetcher):
    route = respx.get(f"https://{PUBLIC}/advisory").mock(
        return_value=httpx.Response(200, text="hi", headers={"content-type": "text/plain"})
    )
    result = fetcher.fetch("https://example.com/advisory")
    request = route.calls.last.request
    assert request.headers["Host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"
    assert request.headers["User-Agent"] == "test-agent"
    assert request.headers["Accept-Encoding"] == "identity"
    assert result.content == b"hi"
    assert result.url == "https://example.com/advisory"
    assert not result.truncated


@respx.mock
def test_redirect_to_internal_address_blocked(fetcher):
    respx.get(f"http://{PUBLIC}/r").mock(
        return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/"})
    )
    with pytest.raises(BlockedURLError):
        fetcher.fetch("http://example.com/r")


@respx.mock
def test_redirect_to_other_public_host_revalidated(fetcher):
    respx.get(f"http://{PUBLIC}/r").mock(
        return_value=httpx.Response(301, headers={"location": "https://cdn.example.net/page"})
    )
    final = respx.get(f"https://{PUBLIC_2}/page").mock(return_value=httpx.Response(200, text="ok"))
    result = fetcher.fetch("http://example.com/r")
    assert final.calls.last.request.headers["Host"] == "cdn.example.net"
    assert result.url == "https://cdn.example.net/page"


@respx.mock
def test_relative_redirect(fetcher):
    respx.get(f"http://{PUBLIC}/a").mock(
        return_value=httpx.Response(302, headers={"location": "/b"})
    )
    respx.get(f"http://{PUBLIC}/b").mock(return_value=httpx.Response(200, text="b"))
    assert fetcher.fetch("http://example.com/a").url == "http://example.com/b"


@respx.mock
def test_redirect_loop_capped(fetcher):
    respx.get(f"http://{PUBLIC}/loop").mock(
        return_value=httpx.Response(302, headers={"location": "/loop"})
    )
    with pytest.raises(BlockedURLError, match="redirects"):
        fetcher.fetch("http://example.com/loop")


@respx.mock
def test_body_size_capped(fetcher):
    respx.get(f"http://{PUBLIC}/big").mock(return_value=httpx.Response(200, content=b"x" * 50))
    result = fetcher.fetch("http://example.com/big")
    assert result.truncated
    assert len(result.content) == 10


@respx.mock
def test_body_exactly_at_cap_not_truncated(fetcher):
    respx.get(f"http://{PUBLIC}/exact").mock(return_value=httpx.Response(200, content=b"y" * 10))
    result = fetcher.fetch("http://example.com/exact")
    assert not result.truncated
    assert result.content == b"y" * 10


@respx.mock
def test_malformed_redirect_is_blocked(fetcher):
    respx.get(f"http://{PUBLIC}/r").mock(
        return_value=httpx.Response(302, headers={"location": "http://[::1"})
    )
    with pytest.raises(BlockedURLError):
        fetcher.fetch("http://example.com/r")


def test_idna_host_resolved_in_ascii_form():
    seen = []

    def resolver(host, port):
        seen.append(host)
        return [PUBLIC]

    with SafeFetcher("ua", resolver=resolver) as f:
        f.validate("https://faß.de/")
    assert seen == ["xn--fa-hia.de"]


def test_client_ignores_env_proxies_and_keepalive(fetcher):
    assert fetcher._client._trust_env is False
