"""Who may use the web interface, and the headers every answer carries.

The model, described for users in docs/WEB.md:

- Each run of ``serve`` makes a fresh random access key. The address it prints carries the key once;
  the first visit trades it for a session cookie (HttpOnly, SameSite=Strict, named for the port,
  because cookies are shared between the ports of one address) and the page moves to an address
  without it. A program can send ``Authorization: Bearer KEY`` instead.
- The Host header must name the address and port being served, so a web page whose own name was
  pointed at 127.0.0.1 (DNS rebinding) is refused.
- Every change is a POST. A browser session must send its form token, and a browser's Origin header,
  or failing that its Sec-Fetch-Site header, must say the request came from this page itself.

Nothing here touches the network; ``server.py`` applies these checks to each request.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

KEY_BYTES = 32
MAX_SESSIONS = 32
MAX_COOKIE_HEADER = 8192
FORM_TOKEN_FIELD = "form_token"
FORM_TOKEN_HEADER = "X-Form-Token"

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self';"
    " form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
# A downloaded report is a document of its own: no script at all, and a sandbox so it has no origin here.
DOWNLOAD_POLICY = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; sandbox"

SECURITY_HEADERS: Tuple[Tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)


def new_key() -> str:
    return secrets.token_urlsafe(KEY_BYTES)


def same_secret(given: Optional[str], expected: str) -> bool:
    """Compares in constant time, so the time taken says nothing about how much of a guess was right."""
    if not given or not expected:
        return False
    return hmac.compare_digest(given.encode("utf-8", "surrogateescape"), expected.encode("utf-8", "surrogateescape"))


@dataclass(frozen=True)
class Session:
    id: str
    form_token: str
    created: float


class Sessions:
    """Browser sessions of this run, in memory only. The oldest is dropped when there are too many."""

    def __init__(self, limit: int = MAX_SESSIONS):
        self.limit = limit
        self._items: "OrderedDict[str, Session]" = OrderedDict()
        self._lock = threading.Lock()

    def create(self) -> Session:
        session = Session(secrets.token_urlsafe(32), secrets.token_urlsafe(32), time.time())
        with self._lock:
            self._items[session.id] = session
            while len(self._items) > self.limit:
                self._items.popitem(last=False)
        return session

    def find(self, values: Sequence[str]) -> Optional[Session]:
        with self._lock:
            known = list(self._items.values())
        for value in values:
            for session in known:
                if same_secret(value, session.id):
                    return session
        return None

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def cookie_name(port: int) -> str:
    return f"evidence_seal_{port}"


def cookie_header(name: str, value: str) -> str:
    return f"{name}={value}; HttpOnly; SameSite=Strict; Path=/"


def cookie_values(header: Optional[str], name: str) -> List[str]:
    """Every value sent for this cookie name. Another server on this address could set one too, so any may be stale."""
    if not header or len(header) > MAX_COOKIE_HEADER:
        return []
    found = []
    for part in header.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key == name and value:
            found.append(value)
    return found[:8]


def bearer_of(header: Optional[str]) -> Optional[str]:
    if header and header[:7].lower() == "bearer ":
        return header[7:].strip()
    return None


def allowed_hosts(host: str, port: int) -> Tuple[str, ...]:
    """The Host header values that name this server: its address and port, and localhost for the usual loopback."""
    shown = f"[{host}]" if ":" in host else host
    names = [shown]
    if host in ("127.0.0.1", "::1"):
        names.append("localhost")
    with_port = [f"{name}:{port}" for name in names]
    return tuple(with_port + (names if port == 80 else []))


def host_allowed(value: Optional[str], allowed: Sequence[str]) -> bool:
    return value is not None and value.strip().lower() in allowed


def origin_allowed(origin: Optional[str], fetch_site: Optional[str], allowed: Sequence[str]) -> bool:
    """A browser names where a POST came from. A program that names nothing still needs the key or a form token."""
    if origin is not None:
        return origin.strip().lower() in {f"http://{name}" for name in allowed}
    if fetch_site is not None:
        return fetch_site.strip().lower() in ("same-origin", "none")
    return True
