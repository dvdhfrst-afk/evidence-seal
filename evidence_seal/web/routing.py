"""Requests, responses and the route table that the pages and the JSON API share.

A route names its method, a path pattern, the handler, and the largest body it accepts, so the
server refuses an oversized body before reading any of it. Path parts are matched by pattern only:
``{sha}`` is a seal's full manifest SHA-256, ``{job}`` a job ID and ``{format}`` a format name.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

FORM_LIMIT = 64 * 1024
UPLOAD_LIMIT = 40 * 1024 * 1024

_PLACEHOLDERS = {
    "{sha}": r"(?P<sha>[0-9a-f]{64})",
    "{job}": r"(?P<job>[0-9a-f]{32})",
    "{format}": r"(?P<format>[a-z0-9]{1,16})",
}
_SAFE_FILE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class HttpError(Exception):
    """An answer other than success, with a code a program can test and a message a person can read."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def not_found(what: str = "this page") -> HttpError:
    return HttpError(404, "not_found", f"{what} does not exist here")


def bad_request(message: str) -> HttpError:
    return HttpError(400, "bad_request", message)


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: List[Tuple[str, str]] = field(default_factory=list)
    download: bool = False


def html_response(text: str, status: int = 200) -> Response:
    return Response(status, text.encode("utf-8"), "text/html; charset=utf-8")


def json_response(data: Any, status: int = 200) -> Response:
    return Response(status, (json.dumps(data, indent=2) + "\n").encode("ascii"), "application/json")


def redirect(location: str) -> Response:
    return Response(303, b"", "text/plain; charset=utf-8", [("Location", location)])


def safe_file_name(stem: str, suffix: str) -> str:
    """A download name made only of plain characters, since the real one may hold anything."""
    plain = _SAFE_FILE_NAME.sub("_", stem).strip("._")[:80]
    return (plain or "evidence-seal") + suffix


def download(data: bytes, media_type: str, filename: str) -> Response:
    return Response(200, data, media_type, [("Content-Disposition", f'attachment; filename="{filename}"')], download=True)


@dataclass
class Request:
    method: str
    path: str
    query: Dict[str, List[str]]
    params: Dict[str, str]
    headers: Any
    body: bytes
    app: Any
    session: Any = None
    fields: Any = None  # inputs.Fields, read by the server before the handler runs

    @property
    def is_api(self) -> bool:
        return self.path.startswith("/api/")

    @property
    def form_token(self) -> str:
        return self.session.form_token if self.session is not None else ""

    def arg(self, name: str, default: Optional[str] = None) -> Optional[str]:
        values = self.query.get(name)
        if not values:
            return default
        if len(values) > 1:
            raise bad_request(f"the address gives {name} more than once")
        return values[0]


Handler = Callable[[Request], Response]


@dataclass(frozen=True)
class Route:
    method: str
    pattern: "re.Pattern[str]"
    handler: Handler
    limit: int


class Router:
    def __init__(self) -> None:
        self.routes: List[Route] = []

    def add(self, method: str, pattern: str, handler: Handler, limit: int = FORM_LIMIT) -> None:
        text = re.escape(pattern)
        for placeholder, regex in _PLACEHOLDERS.items():
            text = text.replace(re.escape(placeholder), regex)
        self.routes.append(Route(method, re.compile(text + r"\Z"), handler, limit if method == "POST" else 0))

    def match(self, method: str, path: str) -> Tuple[Route, Dict[str, str]]:
        allowed = False
        for route in self.routes:
            found = route.pattern.match(path)
            if found is None:
                continue
            if route.method == method:
                return route, found.groupdict()
            allowed = True
        if allowed:
            raise HttpError(405, "method_not_allowed", f"{method} is not used for this address")
        raise not_found()
