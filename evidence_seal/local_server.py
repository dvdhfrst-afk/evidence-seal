"""The local test authority over HTTP: an RFC 3161 server that listens on this computer only.

It answers POST requests of type application/timestamp-query with application/timestamp-reply, and
GET / with a short plain text page. Any address that is not a loopback address is refused, so
nothing on the network can reach it. Request bodies are bounded, reads time out, and request bytes
are parsed as hostile input.

Switches show how stamp handles trouble: refuse every request, answer busy (HTTP 429) a number of
times, wait before answering, sign a fixed time, or answer bytes that are not a token.

Public API: ServeOptions, loopback_host(), LocalServer (start, url, stop, requests, serve_forever;
usable as a context manager), MAX_REQUEST_BYTES.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from .errors import UsageError
from .local_authority import SYSTEM_FAILURE, LocalAuthority

MAX_REQUEST_BYTES = 64 * 1024
READ_TIMEOUT = 10
BROKEN_ANSWER = b"This is not a timestamp token. The test authority was started with --broken.\n"
PAGE = (
    "evidence-seal local test authority (TEST ONLY)\n"
    "\n"
    "POST RFC 3161 timestamp requests here, as application/timestamp-query.\n"
    "Its tokens prove nothing to anyone else: whoever holds its key file can sign any date.\n"
)


@dataclass
class ServeOptions:
    refuse: bool = False
    busy: int = 0
    delay: float = 0.0
    fixed_time: Optional[datetime] = None
    broken: bool = False


def loopback_host(host: str, what: str = "the test authority") -> str:
    """The address to bind, which must be a loopback address. ``localhost`` means 127.0.0.1.

    ``what`` names the server in the refusal."""
    if host.strip().lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        address = None
    if address is None or not address.is_loopback:
        raise UsageError(
            f"{what} listens only on this computer, and {host!r} is not a loopback address."
            " Use 127.0.0.1 or ::1"
        )
    return str(address)


class _Handler(BaseHTTPRequestHandler):
    server_version = "evidence-seal-test-authority"
    sys_version = ""
    timeout = READ_TIMEOUT
    error_content_type = "text/plain; charset=utf-8"
    error_message_format = "Error %(code)d: %(message)s\n"

    def log_message(self, format, *args):  # Requests are reported through the server's log instead
        pass

    def _send(self, status: int, body: bytes, kind: str = "text/plain; charset=utf-8", headers=()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _plain(self, status: int, text: str, headers=()) -> None:
        self.close_connection = True
        self._send(status, (text + "\n").encode("utf-8"), headers=headers)
        self.server.note(f"answered HTTP {status}: {text}")

    def do_GET(self):
        if self.path.split("?", 1)[0] not in ("/", "/tsr"):
            self._plain(404, "Not found. POST timestamp requests to /tsr")
            return
        self._send(200, PAGE.encode("utf-8"))

    def do_POST(self):
        if self.headers.get("Transfer-Encoding"):
            self._plain(411, "Send the request with a Content-Length, not in chunks")
            return
        length_text = (self.headers.get("Content-Length") or "").strip()
        if not length_text:
            self._plain(411, "A Content-Length is needed")
            return
        if not length_text.isascii() or not length_text.isdigit() or len(length_text) > 12:
            self._plain(400, "The Content-Length is not a number")
            return
        length = int(length_text)
        if length > MAX_REQUEST_BYTES:
            self._plain(413, f"A timestamp request is never this large (limit {MAX_REQUEST_BYTES} bytes)")
            return
        body = self.rfile.read(length)
        if len(body) < length:
            self.close_connection = True
            return
        kind = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if kind != "application/timestamp-query":
            self._plain(415, "Send application/timestamp-query")
            return
        server = self.server
        number = server.count_request()
        options = server.options
        if number <= options.busy:
            self._plain(429, f"Busy on purpose (--busy {options.busy}), request {number}", (("Retry-After", "1"),))
            return
        if options.delay and server.stopping.wait(options.delay):
            return
        if options.broken:
            self._send(200, BROKEN_ANSWER, "application/timestamp-reply")
            server.note("answered with bytes that are not a token (--broken)")
            return
        if options.refuse:
            answer = server.authority.refusal(SYSTEM_FAILURE, "this test authority was started with --refuse")
            server.note("refused a request (--refuse)")
        else:
            answer = server.authority.answer(body, options.fixed_time)
            server.note("answered a request")
        self._send(200, answer, "application/timestamp-reply")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows this option would let a second server take the same port silently.
    allow_reuse_address = os.name != "nt"

    def __init__(self, address, authority: LocalAuthority, options: ServeOptions, log):
        self.authority = authority
        self.options = options
        self.log = log
        self.stopping = threading.Event()
        self._lock = threading.Lock()
        self.requests = 0
        super().__init__(address, _Handler)

    def server_bind(self):
        # The base class looks up this computer's full name here, which can wait on the network.
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def count_request(self) -> int:
        with self._lock:
            self.requests += 1
            return self.requests

    def note(self, text: str) -> None:
        if self.log is not None:
            self.log(text)

    def handle_error(self, request, client_address):
        self.note("a request could not be answered: the connection failed or this tool has a bug")


class _Server6(_Server):
    address_family = socket.AF_INET6


class LocalServer:
    """The test authority as a server in this process. Port 0 lets the system choose a free port."""

    def __init__(
        self,
        authority: LocalAuthority,
        host: str = "127.0.0.1",
        port: int = 0,
        options: Optional[ServeOptions] = None,
        log: Optional[Callable[[str], None]] = None,
    ):
        if not 0 <= port <= 65535:
            raise UsageError("--port must be from 0 to 65535")
        self.host = loopback_host(host)
        self.port = port
        self.options = options or ServeOptions()
        self.log = log
        self.authority = authority
        self._server: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None
        self._answered = 0

    def _bind(self) -> _Server:
        kind = _Server6 if ":" in self.host else _Server
        try:
            server = kind((self.host, self.port), self.authority, self.options, self.log)
        except OSError as exc:
            raise UsageError(
                f"could not listen on {self.host} port {self.port}: {exc.strerror or exc}. Choose another port with --port"
            ) from None
        self.port = server.server_address[1]
        self._server = server
        return server

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/tsr"

    @property
    def requests(self) -> int:
        """POST requests of the right type received so far, including any answered busy."""
        return self._server.requests if self._server is not None else self._answered

    def start(self) -> "LocalServer":
        """Listens and answers in a background thread until stop()."""
        server = self._bind()
        self._thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
        self._thread.start()
        return self

    def bind(self) -> "LocalServer":
        """Listens without answering yet, so the URL is known before serve_forever."""
        self._bind()
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
        server.stopping.set()
        if self._thread is not None:
            server.shutdown()
            self._thread.join(5)
        server.server_close()
        self._answered = server.requests
        self._server = None

    def __enter__(self) -> "LocalServer":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()
