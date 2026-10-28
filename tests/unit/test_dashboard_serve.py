import http.client
import socket
import threading

import pytest

from cti.cli import main
from cti.dashboard import serve


@pytest.fixture
def site(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>t</title>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    (dist / ".env").write_text("SECRET=1")  # dotfiles are never served
    (dist / "notes.md").write_text("no MIME type, not served")
    (dist / ".vite").mkdir()
    (dist / ".vite" / "manifest.json").write_text("{}")  # inside a dot-directory
    secret = tmp_path / "secret.json"
    secret.write_text('{"secret": true}')
    (dist / "assets" / "link.json").symlink_to(secret)  # points out of the root
    export = tmp_path / "export"
    export.mkdir()
    (export / "meta.json").write_text('{"ok": true}')
    return dist, export


@pytest.fixture
def server(site):
    srv = serve.make_server(*site, port=0)
    thread = threading.Thread(target=srv.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def request(srv, method="GET", path="/", host=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest(method, path, skip_host=True)
    conn.putheader("Host", host or f"127.0.0.1:{port}")
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


def test_serves_the_allowlist_with_security_headers(server):
    resp, body = request(server, path="/")
    assert resp.status == 200 and body.startswith(b"<!doctype html>")
    assert resp.getheader("Content-Security-Policy") == serve.CSP
    assert "script-src 'self'" in serve.CSP and "unsafe" not in serve.CSP
    for name, value in serve.HEADERS.items():
        assert resp.getheader(name) == value
    resp, body = request(server, path="/data/meta.json")
    assert resp.status == 200 and body == b'{"ok": true}'
    assert resp.getheader("Content-Type") == "application/json; charset=utf-8"
    assert resp.getheader("Cache-Control") == "no-store"
    resp, _ = request(server, path="/assets/app.js?v=1")
    assert resp.status == 200
    assert resp.getheader("Content-Type") == "text/javascript; charset=utf-8"


@pytest.mark.parametrize(
    "path",
    [
        "/../secret.json",
        "/%2e%2e/secret.json",
        "/data/../index.html",
        "/assets/link.json",  # symlink out of the root
        "/.env",
        "/notes.md",
        "/.vite/manifest.json",
        "/data/",
        "/assets/",
        "/index.html%00.js",
    ],
)
def test_anything_off_the_allowlist_is_404(server, path):
    resp, body = request(server, path=path)
    assert resp.status == 404
    assert body == b"404 Not Found\n"
    assert resp.getheader("Content-Security-Policy") == serve.CSP  # headers on errors too


def test_error_bodies_never_echo_the_request(server):
    resp, body = request(server, path="/<script>alert(1)</script>")
    assert resp.status == 404 and b"script" not in body


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1:1", ""])
def test_host_header_must_be_loopback_and_this_port(server, host):
    resp, _ = request(server, host=host or " ")
    assert resp.status == 400
    assert resp.getheader("X-Frame-Options") == "DENY"


def test_localhost_name_is_accepted(server):
    resp, _ = request(server, host=f"localhost:{server.server_address[1]}")
    assert resp.status == 200


def raw(srv, data: bytes) -> bytes:
    with socket.create_connection(srv.server_address, timeout=5) as sock:
        sock.sendall(data)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", b"414"),
        (b"GET / HTTP/9.9\r\n\r\n", b"505"),
        (b"\x00<script> HTTP/1.1\r\n\r\n", b"400"),
    ],
)
def test_malformed_requests_still_get_headers(server, request_bytes, status):
    reply = raw(server, request_bytes)
    assert reply.startswith(b"HTTP/1.0 " + status)
    assert b"Content-Security-Policy: " + serve.CSP.encode() in reply
    assert b"script" not in reply.split(b"\r\n\r\n", 1)[1]


def test_duplicate_host_headers_are_400(server):
    port = server.server_address[1]
    reply = raw(
        server, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nHost: evil.example\r\n\r\n".encode()
    )
    assert reply.startswith(b"HTTP/1.0 400")


def test_route_collision_is_refused(site):
    dist, export = site
    (dist / "data").mkdir()
    (dist / "data" / "meta.json").write_text("{}")
    with pytest.raises(ValueError, match="served from both roots"):
        serve.make_server(dist, export, port=0)


def test_missing_host_header_is_400(server):
    with socket.create_connection(server.server_address, timeout=5) as sock:
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        reply = sock.recv(4096)
    assert reply.startswith(b"HTTP/1.0 400")


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS", "TRACE"])
def test_only_get_and_head(server, method):
    resp, _ = request(server, method=method)
    assert resp.status == 405 and resp.getheader("Allow") == "GET, HEAD"


def test_head_has_no_body(server):
    resp, body = request(server, method="HEAD", path="/data/meta.json")
    assert resp.status == 200 and body == b""
    assert resp.getheader("Content-Length") == "12"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "localhost", "127.0.0.2"])
def test_refuses_to_bind_anywhere_but_loopback(site, host):
    with pytest.raises(ValueError, match=r"127\.0\.0\.1 only"):
        serve.make_server(*site, port=0, host=host)


def test_missing_build_is_a_clear_error(site, tmp_path):
    _, export = site
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FileNotFoundError, match="npm run build"):
        serve.make_server(empty, export, port=0)


def test_cli_serve_needs_an_export(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    assert main(["serve"]) == 2
    assert "run `cti export" in capsys.readouterr().err
    assert main(["serve", "--date", "2026-10-26"]) == 2
    assert "no export for 2026-10-26" in capsys.readouterr().err
