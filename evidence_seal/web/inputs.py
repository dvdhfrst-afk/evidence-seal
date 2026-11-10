"""What a request carries: form fields, JSON fields, uploads, and paths typed into forms.

Everything here is treated as hostile. Bodies are already bounded by the server; this module bounds
the number and size of fields, decodes text strictly, and checks every path a person types before
any other code sees it: it must be a full local path, with no control characters, no ``..``, no
network or device prefix, no alternate data stream, and nothing inside evidence-seal's own folder.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .. import authorities, home, tsp
from ..text import printable
from . import multipart
from .multipart import MultipartError, Part
from .routing import HttpError, bad_request

MAX_FIELDS = 64
MAX_FIELD_LENGTH = 16 * 1024
MAX_PATH_LENGTH = 4096
MAX_PAGE = 100000
MANIFEST_UPLOAD_LIMIT = 32 * 1024 * 1024
UPLOAD_FIELDS = {
    "manifest": MANIFEST_UPLOAD_LIMIT,
    "token": tsp.MAX_TOKEN_BYTES,
    "root": authorities.MAX_ROOT_FILE_BYTES,
    "folder": MAX_PATH_LENGTH * 4,
    "profile": 256,
    "form_token": 256,
}
_YES = ("yes", "on", "true", "1")
_SEPARATORS = re.compile(r"[\\/]+")
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
_DEVICE = re.compile(r"(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]|CONIN\$|CONOUT\$)[ .]*(\..*)?\Z")


@dataclass
class Fields:
    values: Dict[str, List[str]] = field(default_factory=dict)
    files: Dict[str, Part] = field(default_factory=dict)

    def text(self, name: str, required: bool = False, label: Optional[str] = None) -> Optional[str]:
        found = self.values.get(name)
        if not found:
            if required:
                raise bad_request(f"give the {label or name}")
            return None
        if len(found) > 1:
            raise bad_request(f"the field {name} was sent more than once")
        return found[0]

    def lines(self, name: str) -> List[str]:
        """A list: each value of a JSON list, or each non-blank line of a text box."""
        found = self.values.get(name) or []
        items = found if len(found) > 1 else [line for text in found for line in text.splitlines()]
        return [item.strip() for item in items if item.strip()]

    def flag(self, name: str) -> bool:
        value = self.text(name)
        return value is not None and value.strip().lower() in _YES

    def file(self, name: str) -> Optional[Part]:
        return self.files.get(name)


def _media_type(content_type: Optional[str]) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _checked(values: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if sum(len(items) for items in values.values()) > MAX_FIELDS:
        raise bad_request(f"the form has more than {MAX_FIELDS} fields")
    for name, items in values.items():
        if len(name) > 64 or any(len(item) > MAX_FIELD_LENGTH for item in items):
            raise bad_request(f"the field {name[:64]!r} is longer than {MAX_FIELD_LENGTH} characters")
    return values


def _from_form(body: bytes) -> Dict[str, List[str]]:
    try:
        text = body.decode("ascii")
        pairs = urllib.parse.parse_qsl(
            text, keep_blank_values=True, strict_parsing=True, encoding="utf-8", errors="strict", max_num_fields=MAX_FIELDS
        )
    except ValueError:
        raise bad_request("the form could not be read") from None
    values: Dict[str, List[str]] = {}
    for name, value in pairs:
        values.setdefault(name, []).append(value)
    return values


def _from_json(body: bytes) -> Dict[str, List[str]]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise bad_request("the body is not valid JSON") from None
    if not isinstance(data, dict):
        raise bad_request("the JSON body must be an object of named fields")
    values: Dict[str, List[str]] = {}
    for name, value in data.items():
        if isinstance(value, bool):
            values[name] = ["yes" if value else "no"]
        elif isinstance(value, str):
            values[name] = [value]
        elif isinstance(value, list) and len(value) <= MAX_FIELDS and all(isinstance(item, str) for item in value):
            values[name] = list(value) if len(value) != 1 else [value[0]]
        else:
            raise bad_request(f"the field {str(name)[:64]!r} must be text, true or false, or a list of text")
    return values


def _from_multipart(content_type: Optional[str], body: bytes) -> Fields:
    try:
        parts = multipart.parse(body, multipart.boundary_of(content_type), UPLOAD_FIELDS)
    except MultipartError as exc:
        raise bad_request(f"the upload was refused: {exc}") from None
    values: Dict[str, List[str]] = {}
    files: Dict[str, Part] = {}
    for name, part in parts.items():
        if part.is_file:
            files[name] = part
            continue
        try:
            values[name] = [part.data.decode("utf-8")]
        except UnicodeDecodeError:
            raise bad_request(f"the field {name} is not UTF-8 text") from None
    return Fields(_checked(values), files)


def read_fields(content_type: Optional[str], body: bytes) -> Fields:
    """The fields of a POST body, by its Content-Type: a form, JSON, or multipart for uploads."""
    if not body:
        return Fields()
    kind = _media_type(content_type)
    if kind == "application/x-www-form-urlencoded":
        return Fields(_checked(_from_form(body)))
    if kind == "application/json":
        return Fields(_checked(_from_json(body)))
    if kind == "multipart/form-data":
        return _from_multipart(content_type, body)
    raise HttpError(
        415, "unsupported_media_type", "send application/x-www-form-urlencoded, application/json or multipart/form-data"
    )


def _inside(path: str, folder: str) -> bool:
    path, folder = os.path.normcase(path), os.path.normcase(folder)
    return path == folder or path.startswith(folder.rstrip("\\/") + os.sep)


def typed_path(text: str, what: str) -> Path:
    """A path a person typed, after every check above. The thing it names may not exist yet."""
    value = text.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].strip()  # What copying a path from a file manager often adds
    if not value:
        raise bad_request(f"give the {what}")
    if len(value) > MAX_PATH_LENGTH:
        raise bad_request(f"the {what} is longer than {MAX_PATH_LENGTH} characters")
    if printable(value) != value:
        raise bad_request(f"the {what} holds control or formatting characters, so it was not used")
    value = os.path.expanduser(value)
    if value.startswith(("\\\\", "//")):
        raise bad_request(f"the {what} is a network or device path. Give a folder on this computer")
    if not os.path.isabs(value) or (os.name == "nt" and not _WINDOWS_DRIVE.match(value)):
        example = "C:\\Users\\you\\Documents\\work" if os.name == "nt" else "/home/you/work"
        raise bad_request(f"the {what} must be a full path, such as {example}")
    if ".." in _SEPARATORS.split(value):
        raise bad_request(f"the {what} must not contain .. to step out of a folder")
    if os.name == "nt" and ":" in value[2:]:
        raise bad_request(f"the {what} holds a colon after the drive, which would name a hidden stream of a file")
    if os.name == "nt" and any(_DEVICE.match(part) for part in _SEPARATORS.split(value)):
        raise bad_request(f"the {what} uses a name Windows keeps for a device, such as CON or NUL")
    resolved = os.path.realpath(value)
    if resolved.startswith(("\\\\", "//")):  # A link, or a device name such as CON, that leads off this disk
        raise bad_request(f"the {what} leads to a network or device path. Give a folder on this computer")
    if _inside(resolved, os.path.realpath(str(home.home_dir()))):
        raise bad_request(f"the {what} is inside evidence-seal's own folder, which these pages do not touch")
    return Path(resolved)


def existing_folder(text: Optional[str], what: str = "folder") -> Path:
    path = typed_path(text or "", what)
    if not path.is_dir():
        raise bad_request(f"{printable(path)} is not a folder on this computer")
    return path


def new_file(text: str, what: str) -> Path:
    path = typed_path(text, what)
    if path.is_dir():
        raise bad_request(f"{printable(path)} is a folder. Give a file name")
    if not path.parent.is_dir():
        raise bad_request(f"{printable(path.parent)} is not a folder on this computer")
    return path


def page_number(text: Optional[str]) -> int:
    if text is None or text == "":
        return 1
    if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= MAX_PAGE:
        raise bad_request(f"the page must be a whole number from 1 to {MAX_PAGE}")
    return int(text)
