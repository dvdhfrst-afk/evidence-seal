"""The listening side of ``evidence-seal serve``: the only network code in the web interface.

It binds to a loopback address only, using the same check as the local test authority, so nothing
on the network can reach it. Each request is checked in this order before any page or API handler
runs: the number of headers, the Host header, the address, the route, the access key or session,
for a POST the Origin and the body's size and form token. Every answer carries the security headers
in ``security.py``. Concurrent connections, request bodies, uploads and jobs are all bounded.

Public API: WebServer (bind, start, serve_forever, stop, url, address, key, app; usable as a context
manager), MAX_HEADERS, MAX_TARGET, MAX_CONNECTIONS, READ_TIMEOUT.
"""

from __future__ import annotations

import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from ..errors import EvidenceSealError, UsageError
from ..local_server import close_gently, loopback_host
from ..text import printable
from . import api, pages, security
from .assets import ASSETS
from .inputs import MAX_FIELDS, Fields, read_fields
from .jobs import BUG_TEXT, JobRunner, TooManyJobs
from .routing import HttpError, Request, Response, Router, json_response, redirect

MAX_HEADERS = 50
MAX_TARGET = 8192
MAX_CONNECTIONS = 32
READ_TIMEOUT = 30
_STATUS_CODES = {400: "bad_request", 408: "timeout", 414: "address_too_long", 431: "headers_too_large", 501: "method_not_allowed", 505: "bad_version"}


def build_router() -> Router:
    router = Router()
    pages.register(router)
    api.register(router)
    for name, (kind, data) in ASSETS.items():
        router.add("GET", f"/assets/{name}", lambda request, kind=kind, data=data: Response(200, data, kind))
    return router


class App:
    """The state of one run: its key, sessions, jobs and routes."""

    def __init__(self, host: str, port: int, key: str, profile: Optional[str]):
        self.host = host
        self.port = port
        self.key = key
        self.profile = profile
        self.allowed = security.allowed_hosts(host, port)
        self.cookie = security.cookie_name(port)
        self.sessions = security.Sessions()
        self.runner = JobRunner()
        self.router = build_router()


def error_response(error: HttpError, is_api: bool) -> Response:
    if is_api:
        return json_response({"error": {"code": error.code, "message": printable(error.message)}}, error.status)
    return pages.error_page(error)


def _first(values: Optional[List[str]]) -> Optional[str]:
    return values[0] if values else None


class _Handler(BaseHTTPRequestHandler):
    server_version = "evidence-seal"
    sys_version = ""
    timeout = READ_TIMEOUT

    def log_message(self, format, *args):  # Nothing about requests is printed: addresses can carry the key
        pass

    def parse_request(self):
        if not super().parse_request():
            return False
        if self.request_version == "HTTP/0.9":
            self.send_error(400)
            return False
        return True

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def send_error(self, code, message=None, explain=None):
        """What http.server answers for a request it cannot read at all, with the same headers as any answer."""
        self.close_connection = True
        if getattr(self, "request_version", "HTTP/0.9") == "HTTP/0.9":
            self.request_version = "HTTP/1.0"  # Otherwise the answer would go without its status line and headers
        path = str(getattr(self, "path", "") or "")
        text = {
            400: "the request could not be read",
            408: "the request took too long to arrive",
            414: "the address is too long",
            431: "the request has too many headers, or a header is too long",
            501: "this method is not used here",
            505: "use HTTP/1.0 or HTTP/1.1",
        }.get(code, "the request could not be answered")
        self._write(error_response(HttpError(code, _STATUS_CODES.get(code, "bad_request"), text), path.startswith("/api/")))

    def _serve(self, method: str) -> None:
        app: App = self.server.app  # type: ignore[attr-defined]
        is_api = self.path.startswith("/api/")
        try:
            response = self._answer(app, method)
        except HttpError as exc:
            response = error_response(exc, is_api)
        except TooManyJobs as exc:
            response = error_response(HttpError(503, "too_many_jobs", str(exc)), is_api)
        except UsageError as exc:
            response = error_response(HttpError(400, "bad_request", str(exc)), is_api)
        except EvidenceSealError as exc:
            response = error_response(HttpError(409, "not_done", str(exc)), is_api)
        except OSError as exc:
            where = f"{exc.filename}: " if exc.filename else ""
            response = error_response(HttpError(500, "file_error", f"{where}{exc.strerror or exc}. Nothing was changed."), is_api)
        except Exception as exc:  # A bug must not show a stack trace, or look like a result
            response = error_response(HttpError(500, "bug", BUG_TEXT.format(name=type(exc).__name__)), is_api)
        self._write(response)

    def _answer(self, app: App, method: str) -> Response:
        if len(self.headers) > MAX_HEADERS:
            self.close_connection = True
            raise HttpError(431, "headers_too_large", f"the request has more than {MAX_HEADERS} headers")
        if not security.host_allowed(self.headers.get("Host"), app.allowed):
            self.close_connection = True
            raise HttpError(
                400, "wrong_host", f"this server answers only to http://{app.allowed[0]}/, the address serve printed"
            )
        if len(self.path) > MAX_TARGET:
            raise HttpError(414, "address_too_long", "the address is too long")
        if not self.path.startswith("/") or self.path.startswith("//"):
            raise HttpError(400, "bad_request", "the address must be a path on this server")
        parts = urllib.parse.urlsplit(self.path)
        try:
            query: Dict[str, List[str]] = urllib.parse.parse_qs(
                parts.query, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=MAX_FIELDS
            )
        except ValueError:
            raise HttpError(400, "bad_request", "the address's query cannot be read") from None
        route, params = app.router.match(method, parts.path)
        by_key = False
        bearer = security.bearer_of(self.headers.get("Authorization"))
        if bearer is not None:
            if not security.same_secret(bearer, app.key):
                raise HttpError(401, "wrong_key", "this access key is not the one for this run of serve")
            by_key = True
        session = None if by_key else app.sessions.find(security.cookie_values(self.headers.get("Cookie"), app.cookie))
        if method == "GET" and "key" in query and not parts.path.startswith("/api/"):
            return self._sign_in(app, parts.path, query)
        if session is None and not by_key:
            self.close_connection = True
            raise HttpError(
                401, "no_key", "open the address that serve printed, which carries this run's access key, or send Authorization: Bearer KEY"
            )
        fields = Fields()
        body = b""
        if method == "POST":
            if not security.origin_allowed(self.headers.get("Origin"), self.headers.get("Sec-Fetch-Site"), app.allowed):
                self.close_connection = True
                raise HttpError(403, "cross_origin", "this request came from another web page, so it was refused. Nothing was changed")
            body = self._read_body(route.limit)
            fields = read_fields(self.headers.get("Content-Type"), body)
            if not by_key:
                token = fields.text(security.FORM_TOKEN_FIELD) or self.headers.get(security.FORM_TOKEN_HEADER)
                if not security.same_secret(token, session.form_token):  # type: ignore[union-attr]
                    raise HttpError(
                        403, "form_token", "the form token is missing or out of date. Reload the page and try again. Nothing was changed"
                    )
        elif self.headers.get("Content-Length", "0").strip() not in ("", "0") or self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise HttpError(400, "bad_request", "a GET request has no body")
        request = Request(method, parts.path, query, params, self.headers, body, app, session, fields)
        return route.handler(request)

    def _sign_in(self, app: App, path: str, query: Dict[str, List[str]]) -> Response:
        """Trades the access key in the address for a session cookie, and moves to the address without it."""
        if not security.same_secret(_first(query.get("key")), app.key):
            raise HttpError(401, "wrong_key", "this access key is not the one for this run of serve")
        session = app.sessions.create()
        rest = [(name, value) for name, values in query.items() if name != "key" for value in values]
        response = redirect(path + ("?" + urllib.parse.urlencode(rest) if rest else ""))
        response.headers.append(("Set-Cookie", security.cookie_header(app.cookie, session.id)))
        return response

    def _read_body(self, limit: int) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise HttpError(411, "length_required", "send the body with a Content-Length, not in chunks")
        text = (self.headers.get("Content-Length") or "").strip()
        if not text:
            self.close_connection = True
            raise HttpError(411, "length_required", "a POST needs a Content-Length")
        if not text.isascii() or not text.isdigit() or len(text) > 12:
            self.close_connection = True
            raise HttpError(400, "bad_request", "the Content-Length is not a number")
        length = int(text)
        if length > limit:
            self.close_connection = True
            raise HttpError(413, "too_large", f"the body is larger than this address accepts ({limit} bytes). Nothing was read")
        data = self.rfile.read(length)
        if len(data) < length:
            self.close_connection = True
            raise HttpError(400, "bad_request", "the body ended before its Content-Length")
        return data

    def _write(self, response: Response) -> None:
        try:
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            policy = security.DOWNLOAD_POLICY if response.download else security.CONTENT_SECURITY_POLICY
            self.send_header("Content-Security-Policy", policy)
            for name, value in security.SECURITY_HEADERS + tuple(response.headers):
                self.send_header(name, value)
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response.body)
        except OSError:
            self.close_connection = True  # The other side went away


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address):
        self.app: Any = None
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, _Handler)

    def server_bind(self):
        # The base class looks up this computer's full name here, which can wait on the network.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # On Windows another program could otherwise bind the same port and receive the browser's key.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            # Too many connections at once: this one is closed unanswered, without waiting on it
            ThreadingHTTPServer.shutdown_request(self, request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def shutdown_request(self, request):
        close_gently(request)

    def handle_error(self, request, client_address):
        pass  # A broken connection is not worth a stack trace; every answer already handles its own errors


class _Server6(_Server):
    address_family = socket.AF_INET6


class WebServer:
    """The web interface in this process. Port 0 lets the system choose a free port."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, profile: Optional[str] = None):
        if not 0 <= port <= 65535:
            raise UsageError("--port must be from 0 to 65535")
        self.host = loopback_host(host, "the web interface")
        self.port = port
        self.profile = profile
        self.key = security.new_key()
        self.app: Optional[App] = None
        self._server: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None

    def bind(self) -> "WebServer":
        kind = _Server6 if ":" in self.host else _Server
        try:
            server = kind((self.host, self.port))
        except OSError as exc:
            raise UsageError(
                f"could not listen on {self.host} port {self.port}: {exc.strerror or exc}. Choose another port with --port"
            ) from None
        self.port = server.server_address[1]
        self.app = App(self.host, self.port, self.key, self.profile)
        server.app = self.app
        self._server = server
        return self

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/"

    @property
    def address(self) -> str:
        """The address to open, which carries this run's access key."""
        return f"{self.url}?key={self.key}"

    def start(self) -> "WebServer":
        """Listens and answers in a background thread until stop()."""
        server = self.bind()._server
        assert server is not None
        self._thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        """Answers in this thread until interrupted. Call bind() first."""
        assert self._server is not None, "bind() comes first"
        try:
            self._server.serve_forever(0.2)
        finally:
            self.stop()

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        self._server = None
        if self._thread is not None:
            server.shutdown()
            self._thread.join(5)
        server.server_close()
        if self.app is not None:
            self.app.runner.stop()

    def __enter__(self) -> "WebServer":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()
