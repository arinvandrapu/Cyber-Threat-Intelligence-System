"""``cti serve``: the dashboard on 127.0.0.1, read-only, with strict headers (Phase 8).

Deliberately not ``SimpleHTTPRequestHandler``: that maps URL paths onto the filesystem, so
traversal, symlinks and directory listings are its problems to get right. Here the server
builds an allowlist at startup (URL path -> file) from two roots, the built dashboard
(``web/dist``) under ``/`` and the export (``data/export/<date>``) under ``/data/``, and a
request is an exact dictionary lookup. Anything else is a 404 with a fixed body.

- **Loopback only.** Binding anywhere but 127.0.0.1 is refused.
- **DNS rebinding.** The Host header must be ``127.0.0.1:<port>`` or ``localhost:<port>``;
  a page on another origin that resolves its name to 127.0.0.1 still sends its own Host,
  so it gets a 400.
- **Headers on every response, errors included:** a strict CSP (no inline script or
  style, no remote anything, no framing), nosniff, no referrer, same-origin COOP/CORP, a
  Permissions-Policy that only allows clipboard writes, and ``no-store`` for data.
- **Methods.** GET and HEAD; anything else is 405. HTTP/1.0 only: no keep-alive.
- **Scope.** Loopback-only and single-user: threads are uncapped and the 10 s timeout is
  per read, so a local process could hold connections open. Not built for a network.
"""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CSP = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'none'",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "require-trusted-types-for 'script'",
    )
)
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), clipboard-write=(self)",
    "X-Frame-Options": "DENY",
}
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
    ".woff2": "font/woff2",
}
TIMEOUT_SECONDS = 10


def allowlist(dist: Path, export: Path) -> dict[str, Path]:
    """URL path -> file for every servable file; nothing outside the two roots."""
    routes: dict[str, Path] = {}
    for root, prefix in ((dist, "/"), (export, "/data/")):
        root = root.resolve(strict=True)
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root)
            if any(part.startswith(".") for part in rel.parts) or not path.is_file():
                continue  # no dotfiles, nothing inside dot-directories (.vite/, .git/)
            real = path.resolve()
            if not real.is_relative_to(root):  # a symlink pointing out of the root
                continue
            if path.suffix.lower() not in MIME:
                continue
            url = prefix + rel.as_posix()
            if url in routes:
                raise ValueError(f"{url} is served from both roots; remove one")
            routes[url] = real
    if "/index.html" not in routes:
        raise FileNotFoundError(f"{dist} has no index.html; run `npm run build` in web/")
    routes["/"] = routes["/index.html"]
    return routes


HOST = "127.0.0.1"


def check_loopback(host: str) -> None:
    if host != HOST:
        raise ValueError(f"refusing to bind {host!r}: the dashboard serves {HOST} only")


def make_handler(routes: dict[str, Path], port: int) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"{HOST}:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "cti"
        sys_version = ""
        timeout = TIMEOUT_SECONDS
        # set before parsing, so a request rejected while parsing (414, 505, ...) can still
        # be logged and answered with the full header set
        path = ""
        command = None
        # never fall back to HTTP/0.9 (a bare body: no status line, so no headers at all)
        default_request_version = "HTTP/1.0"

        def end_headers(self) -> None:
            for name, value in HEADERS.items():
                self.send_header(name, value)
            super().end_headers()

        def _plain(self, status: HTTPStatus, extra: dict[str, str] | None = None) -> None:
            body = f"{status.value} {status.phrase}\n".encode()  # never echoes the request
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def send_error(self, code, message=None, explain=None) -> None:
            # the base class would echo the request line into an HTML error page
            self._plain(HTTPStatus(code))

        def _serve(self) -> None:
            hosts = self.headers.get_all("Host") or []
            if len(hosts) != 1 or hosts[0].lower() not in allowed_hosts:
                return self._plain(HTTPStatus.BAD_REQUEST)
            path = self.path.split("?", 1)[0].split("#", 1)[0]
            file = routes.get(path)
            if file is None:
                return self._plain(HTTPStatus.NOT_FOUND)
            body = file.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", MIME[file.suffix.lower()])
            self.send_header("Content-Length", str(len(body)))
            cache = "no-store" if path.startswith("/data/") else "no-cache"
            self.send_header("Cache-Control", cache)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return None

        def do_GET(self) -> None:
            self._serve()

        def do_HEAD(self) -> None:
            self._serve()

        def _not_allowed(self) -> None:
            self._plain(HTTPStatus.METHOD_NOT_ALLOWED, {"Allow": "GET, HEAD"})

        do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _not_allowed

        def log_message(self, fmt: str, *args) -> None:
            # status and path only, non-printables replaced: request lines can carry anything
            if len(args) >= 2:
                path = "".join(c if c.isprintable() else "?" for c in str(self.path)[:200])
                print(f"  {args[1]} {self.command or '-'} {path}", flush=True)

    return Handler


def make_server(dist: Path, export: Path, port: int, host: str = HOST) -> ThreadingHTTPServer:
    """Bound but not yet serving. ``port=0`` picks a free port (the Host check uses it)."""
    check_loopback(host)
    routes = allowlist(dist, export)
    server = ThreadingHTTPServer((host, port), BaseHTTPRequestHandler)
    server.RequestHandlerClass = make_handler(routes, server.server_address[1])
    server.daemon_threads = True
    return server
