"""Settings and named profiles, kept in one INI file that a person can edit by hand.

The file is ``settings.ini`` in the home folder (see ``home.py``), or another file named with
``--settings``. It has its own reader and writer, because people write comments in it: changing a
value through a command rewrites only that value's lines, and every other byte stays as it was,
including comments, blank lines, order, line endings and a byte order mark. docs/SETTINGS.md
describes the file for users.

What other parts of the tool can use:

- ``settings_for(file, profile, ignore)`` returns a ``Resolved``: the value of every key in ``KEYS``
  and where it came from, after the profile, then ``[defaults]``, then the built-in value.
  ``Resolved.library`` is the on/off switch for recording into the library.
- ``resolve_authority(value)`` turns an ``authority`` value into a URL, or into the name of an entry in
  the authority list. It is the one place that decides which.
- ``report-format`` accepts exactly ``report_formats.FORMAT_NAMES``.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import authorities, hashes, home, report_formats, scan, sealing, stamping, trust
from .console import self_command, shown
from .errors import UsageError
from .text import printable

FILE_NAME = "settings.ini"
VERSION = 1
MAX_FILE_BYTES = 1024 * 1024
MAX_NAME_LENGTH = 64
MAX_PROBLEMS = 100
INDENT = "    "
NEW_FILE_TEXT = (
    "# evidence-seal settings. Edit this file by hand, or with the config and profile commands.\n"
    "# A line that starts with # or ; is a comment. docs/SETTINGS.md describes every key.\n"
    "\n"
    "[settings]\n"
    f"version = {VERSION}\n"
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_BYTE_ORDER_MARKS = ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
_SECTION_WORDS = ("settings", "defaults", "profile")


class _Bad(Exception):
    """A value that is not allowed. ``index`` says which of a key's values it was."""

    def __init__(self, reason: str, index: int = 0):
        super().__init__(reason)
        self.reason = reason
        self.index = index


# Checks on single values, shared by the command line and the settings file.


def positive_seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from None
    if not 0 < value < 86400:
        raise argparse.ArgumentTypeError("must be more than 0 and less than a day, in seconds")
    return value


def retry_count(text: str) -> int:
    if not text.isascii() or not text.isdigit() or int(text) > 10:
        raise argparse.ArgumentTypeError("must be a whole number from 0 to 10")
    return int(text)


def name_problem(name: str) -> Optional[str]:
    """Why this cannot be a profile name, or None when it can."""
    if len(name) > MAX_NAME_LENGTH:
        return f"is longer than {MAX_NAME_LENGTH} characters"
    if not _NAME.match(name):
        return "may use only letters, digits, hyphens, underscores and dots, and must start with a letter or digit"
    return None


def template_problem(template: str) -> Optional[str]:
    """Why this cannot be a purpose template, or None when it can."""
    try:
        parts = list(string.Formatter().parse(template))
    except ValueError:
        return "has a { or } that opens or closes nothing; write {{ or }} for a brace itself"
    for _, name, spec, conversion in parts:
        if name is not None and (name not in ("folder", "date") or spec or conversion):
            return f"may use {{folder}} and {{date}} only, not {{{name}}}"
    return None


def expand_purpose(template: str, folder: str, created: str) -> str:
    """Fills in a purpose template. ``created`` is the manifest's created field."""
    return template.format(folder=folder, date=created[:10])


def resolve_authority(value: str) -> Tuple[Optional[str], Optional[str]]:
    """An ``authority`` value as (URL, None) for an address, or (None, name) for an authority list entry."""
    if value.lower().startswith(("http://", "https://")):
        return value, None
    entry = authorities.find(value)
    if entry is None:
        raise UsageError(
            f"the authority name {value!r} is not known. See the names with: authority list,"
            " or give the authority's http:// or https:// URL"
        )
    return None, entry.name


def _converted(convert: Callable[[str], object]) -> Callable[[str, Path], object]:
    def check(value: str, base: Path) -> object:
        try:
            return convert(value)
        except argparse.ArgumentTypeError as exc:
            raise _Bad(str(exc)) from None

    return check


def _authority(value: str, base: Path) -> str:
    if value.lower().startswith(("http://", "https://")):
        try:
            stamping.check_url(value)
        except UsageError as exc:
            raise _Bad(str(exc)) from None
    return value


def _hash(value: str, base: Path) -> str:
    algorithm = hashes.by_name(value)
    if algorithm is None or algorithm.weak:
        raise _Bad(f"must be a strong hash such as sha256, sha384 or sha512, not {value!r}")
    return value


def _policy(value: str, base: Path) -> str:
    problem = stamping.policy_problem(value)
    if problem is not None:
        raise _Bad(problem)
    return value


def _path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    return Path(os.path.normpath(path if path.is_absolute() else base / path))


def _pattern(value: str, base: Path) -> str:
    if scan.parse_rule(value) is None:
        raise _Bad(f"the pattern {value!r} has nothing to match")
    return value


def _choice(*words: str) -> Callable[[str, Path], bool]:
    def check(value: str, base: Path) -> bool:
        if value.lower() not in words:
            raise _Bad(f"must be {words[0]} or {words[1]}, not {value!r}")
        return value.lower() == words[0]

    return check


def _report_format(value: str, base: Path) -> str:
    if value not in report_formats.FORMAT_NAMES:
        raise _Bad(f"must be one of {', '.join(report_formats.FORMAT_NAMES)}, not {value!r}")
    return value


def _purpose(value: str, base: Path) -> str:
    problem = template_problem(value)
    if problem is not None:
        raise _Bad(problem)
    return value


@dataclass(frozen=True)
class Key:
    name: str
    many: bool
    default: object
    check: Callable[[str, Path], object]
    is_path: bool = False

    def text_of(self, value: object) -> List[str]:
        """How a value is written, one line per item. An empty list means none."""
        if value is None:
            return []
        if isinstance(value, bool):
            return [("on" if value else "off") if self.name == "library" else ("yes" if value else "no")]
        if isinstance(value, float) and value.is_integer():
            return [str(int(value))]
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]

    def json_of(self, value: object) -> object:
        return [str(item) for item in value] if isinstance(value, list) else value


KEYS: Dict[str, Key] = {
    key.name: key
    for key in (
        Key("authority", False, trust.DEFAULT_TSA_URL, _authority),
        Key("timeout", False, stamping.DEFAULT_TIMEOUT, _converted(positive_seconds)),
        Key("retries", False, stamping.DEFAULT_RETRIES, _converted(retry_count)),
        Key("hash", False, "sha256", _hash),
        Key("policy", False, None, _policy),
        Key("ca", True, [], _path, is_path=True),
        Key("untrusted", True, [], _path, is_path=True),
        Key("exclude", True, [], _pattern),
        Key("exclude-from", True, [], _path, is_path=True),
        Key("allow-added", False, False, _choice("yes", "no")),
        Key("openssl", False, False, _choice("yes", "no")),
        Key("report-format", False, report_formats.FORMAT_NAMES[0], _report_format),
        Key("purpose", False, None, _purpose),
        Key("library", False, True, _choice("on", "off")),
    )
}


def built_in(name: str) -> object:
    return KEYS[name].default


def _did_you_mean(word: str, choices: Sequence[str]) -> str:
    match = difflib.get_close_matches(word.lower(), list(choices), n=1, cutoff=0.6)
    return f"; did you mean {match[0]!r}?" if match else ""


def known_key(name: str) -> Key:
    if name not in KEYS:
        hint = _did_you_mean(name, KEYS) or "."
        raise UsageError(f"there is no setting {name!r}{hint} The settings are: {', '.join(KEYS)}")
    return KEYS[name]


def check_values(key: Key, values: Sequence[str], base: Path) -> object:
    """The value of a key from its written values, or _Bad saying why not."""
    if not key.many:
        if len(values) != 1:
            raise _Bad("has no value. Give one, or remove the line to use the default" if not values else f"takes one value, but has {len(values)}")
        return key.check(values[0], base)
    found = []
    for index, value in enumerate(values):
        try:
            found.append(key.check(value, base))
        except _Bad as exc:
            raise _Bad(exc.reason, index) from None
    return found


def check_given(key: Key, values: Sequence[str]) -> None:
    """Refuses values given to a command, with the same reasons the file would get."""
    try:
        check_values(key, values, Path.cwd())
    except _Bad as exc:
        raise UsageError(f"{key.name}: {exc.reason}") from None


# The file itself.


@dataclass
class Entry:
    key: str
    lines: List[int]  # the key line, then each line that continues it, as indexes into Document.lines
    values: List[str]
    value_lines: List[int]


@dataclass
class Section:
    kind: str  # settings, defaults or profile
    name: Optional[str]
    header: int
    entries: List[Entry] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"[profile {self.name}]" if self.kind == "profile" else f"[{self.kind}]"

    @property
    def origin(self) -> str:
        return f"profile {self.name}" if self.kind == "profile" else self.kind

    def last_line(self) -> int:
        return max([self.header] + [index for entry in self.entries for index in entry.lines])

    def find(self, key: str) -> List[Entry]:
        return [entry for entry in self.entries if entry.key == key]


@dataclass(frozen=True)
class Problem:
    line: Optional[int]  # counted from 1
    message: str
    structural: bool  # the file cannot be read reliably, so no command may change it

    def describe(self, path: Path) -> str:
        return f"{path} line {self.line}: {self.message}" if self.line else f"{path}: {self.message}"


def bad_character(text: str) -> Optional[str]:
    return next((char for char in text if char != "\t" and printable(char) != char), None)


class Document:
    """One settings file as lines, with what they mean and what is wrong with them."""

    def __init__(self, path: Path, data: bytes):
        self.path = Path(path)
        self.raw = data
        self.base = Path(os.path.abspath(path)).parent
        self.prefix = b""
        self.encoding = "utf-8"
        self.lines: List[Tuple[str, str]] = []  # text and line ending
        self.sections: List[Section] = []
        self._by_name: Dict[Tuple[str, Optional[str]], Section] = {}
        self.problems: List[Problem] = []
        self.values: Dict[Tuple[str, str], object] = {}
        self._read(data)
        self.problems.sort(key=lambda problem: problem.line or 0)
        if len(self.problems) > MAX_PROBLEMS:
            del self.problems[MAX_PROBLEMS:]
            self.problems.append(Problem(None, f"has more than {MAX_PROBLEMS} problems, and only some are listed", True))

    def _problem(self, line: Optional[int], message: str, structural: bool = False) -> None:
        self.problems.append(Problem(line, message, structural))

    @property
    def _too_many(self) -> bool:
        return len(self.problems) > MAX_PROBLEMS

    @property
    def newline(self) -> str:
        return next((ending for _, ending in self.lines if ending), "\n")

    def section(self, kind: str, name: Optional[str] = None) -> Optional[Section]:
        return self._by_name.get((kind, name))

    def profiles(self) -> List[Section]:
        return [found for found in self.sections if found.kind == "profile"]

    def render(self, lines: Sequence[Tuple[str, str]]) -> bytes:
        return self.prefix + "".join(text + ending for text, ending in lines).encode(self.encoding)

    def _read(self, data: bytes) -> None:
        if len(data) > MAX_FILE_BYTES:
            self._problem(None, f"is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB, far more than settings need", True)
            return
        for mark, encoding in _BYTE_ORDER_MARKS:
            if data.startswith(mark):
                self.prefix, self.encoding = mark, encoding
                break
        try:
            text = data[len(self.prefix) :].decode(self.encoding)
        except UnicodeDecodeError as exc:
            if self.encoding == "utf-8":
                line = data[: len(self.prefix) + exc.start].count(b"\n") + 1
                self._problem(line, "is not UTF-8 text. Save the file as UTF-8", True)
            else:
                self._problem(None, "is not readable UTF-16 text. Save the file as UTF-8", True)
            return
        pieces = text.split("\n")
        for index, piece in enumerate(pieces):
            if index == len(pieces) - 1:
                if piece:
                    self.lines.append((piece, ""))
            elif piece.endswith("\r"):
                self.lines.append((piece[:-1], "\r\n"))
            else:
                self.lines.append((piece, "\n"))
        self._parse()
        version = self._newer_version()
        if version is not None:
            self.problems = [
                Problem(
                    version[0],
                    f"is settings version {version[1]}, written by a newer evidence-seal, and this one reads version"
                    f" {VERSION}. The file was not used and not changed. Use a newer evidence-seal, or add --no-settings",
                    True,
                )
            ]
            self.values = {}
            return
        self._check_entries()

    def _parse(self) -> None:
        current: Optional[Section] = None
        entry: Optional[Entry] = None
        skipping = False  # after an unreadable section line, until the next good one
        after_bad = False  # after an unreadable line, whose indented lines would only repeat the problem
        for index, (text, _) in enumerate(self.lines):
            if self._too_many:
                break
            number = index + 1
            bad = bad_character(text)
            if bad is not None:
                self._problem(number, f"holds a character that has no place in a settings file ({printable(bad)})", True)
                entry = None
                after_bad = True
                continue
            stripped = text.strip()
            if not stripped or stripped[0] in "#;":
                continue
            if text[0] in " \t":
                if entry is not None:
                    entry.lines.append(index)
                    entry.values.append(stripped)
                    entry.value_lines.append(index)
                elif not skipping and not after_bad:
                    self._problem(number, "this indented line does not follow a key. Remove the indent, or the line", True)
                continue
            entry = None
            after_bad = False
            if text.startswith("["):
                current = self._header(number, stripped)
                skipping = current is None
                continue
            if skipping:
                continue
            key, equals, value = text.partition("=")
            key = key.strip()
            if not equals or not key:
                shown_text = stripped if len(stripped) <= 60 else stripped[:57] + "..."
                self._problem(number, f"expected KEY = VALUE or a [section] line, not {shown_text!r}", True)
                after_bad = True
                continue
            if current is None:
                self._problem(number, f"{key} is above every section. Put it under [defaults] or a [profile NAME]", True)
                after_bad = True
                continue
            value = value.strip()
            entry = Entry(key, [index], [value] if value else [], [index] if value else [])
            current.entries.append(entry)

    def _header(self, number: int, stripped: str) -> Optional[Section]:
        if not stripped.endswith("]"):
            self._problem(number, "a section line must end with ], and a comment goes on a line of its own", True)
            return None
        words = stripped[1:-1].split()
        if len(words) == 1 and words[0] in ("settings", "defaults"):
            kind, name = words[0], None
        elif len(words) == 2 and words[0] == "profile":
            kind, name = "profile", words[1]
            reason = name_problem(name)
            if reason is not None:
                self._problem(number, f"the profile name {name!r} {reason}", True)
                return None
        elif words == ["profile"]:
            self._problem(number, "[profile] needs a name, as in [profile work]", True)
            return None
        else:
            self._problem(
                number,
                f"there is no section {stripped}{_section_hint(words)}. The sections are [settings], [defaults] and [profile NAME]",
                True,
            )
            return None
        earlier = self.section(kind, name)
        if earlier is not None:
            self._problem(number, f"{earlier.label} appears twice; the first is on line {earlier.header + 1}. Merge them into one", True)
            return None
        found = Section(kind, name, number - 1)
        self.sections.append(found)
        self._by_name[(kind, name)] = found
        return found

    def _newer_version(self) -> Optional[Tuple[int, int]]:
        found = self.section("settings")
        for entry in found.find("version") if found else []:
            if len(entry.values) == 1 and entry.values[0].isascii() and entry.values[0].isdigit():
                if int(entry.values[0]) > VERSION:
                    return entry.lines[0] + 1, int(entry.values[0])
        return None

    def _check_entries(self) -> None:
        for section in self.sections:
            allowed: Sequence[str] = ("version",) if section.kind == "settings" else tuple(KEYS)
            seen: Dict[str, int] = {}
            for entry in section.entries:
                if self._too_many:
                    return
                number = entry.lines[0] + 1
                if entry.key not in allowed:
                    hint = _did_you_mean(entry.key, allowed) or f". {section.label} can hold: {', '.join(allowed)}"
                    self._problem(number, f"there is no setting {entry.key!r} in {section.label}{hint}")
                    continue
                if entry.key in seen:
                    self._problem(number, f"{entry.key} is set twice in {section.label}; the first is on line {seen[entry.key]}. Keep one")
                    continue
                seen[entry.key] = number
                if section.kind == "settings":
                    if entry.values != [str(VERSION)]:
                        self._problem(number, f"version must be {VERSION}, not {' '.join(entry.values) or 'empty'}")
                    continue
                try:
                    self.values[(section.label, entry.key)] = check_values(KEYS[entry.key], entry.values, self.base)
                except _Bad as exc:
                    line = entry.value_lines[exc.index] + 1 if entry.value_lines else number
                    self._problem(line, f"{entry.key} in {section.label}: {exc.reason}")

    def section_problems(self) -> int:
        return sum(1 for problem in self.problems if not problem.structural)


def _section_hint(words: List[str]) -> str:
    if not words:
        return ""
    match = difflib.get_close_matches(words[0].lower(), _SECTION_WORDS, n=1, cutoff=0.6)
    if match == ["profile"] and len(words) == 2:
        return f"; did you mean [profile {words[1]}]?"
    if match and match[0] != "profile" and len(words) == 1:
        return f"; did you mean [{match[0]}]?"
    if len(words) == 1 and name_problem(words[0]) is None:
        return f"; did you mean [profile {words[0]}]?"
    return ""


def default_path() -> Path:
    return home.home_dir() / FILE_NAME


def read_document(path: Path, required: bool) -> Optional[Document]:
    """The settings file, or None when it does not exist and was not asked for by name."""
    path = Path(path)
    if path.is_dir():
        raise UsageError(f"the settings file {path} is a folder")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        if required:
            raise UsageError(f"the settings file {path} does not exist") from None
        return None
    except OSError as exc:
        raise UsageError(f"cannot read the settings file {path}: {exc.strerror or exc}") from None
    return Document(path, data)


def _ended(text: str) -> str:
    return text if text.endswith((".", "?")) else text + "."


def _check_hint(path: Path) -> str:
    option = "" if path == default_path() else f" --settings {shown(path)}"
    return f"run {self_command()} config check{option} to list every problem"


def require_usable(document: Document) -> None:
    """Refuses a file with any problem, since a mistyped key would otherwise be quietly ignored."""
    if document.problems:
        more = len(document.problems) - 1
        extra = f" (and {more} more {'problem' if more == 1 else 'problems'})" if more else ""
        raise UsageError(
            f"{_ended(document.problems[0].describe(document.path) + extra)} No command uses this settings file until it is"
            f" fixed: {_check_hint(document.path)}, or add --no-settings to run without it"
        )


def require_editable(document: Document) -> None:
    """Refuses to change a file whose lines cannot all be read. A wrong value can be fixed by setting it."""
    structural = [problem for problem in document.problems if problem.structural]
    if structural:
        raise UsageError(f"{_ended(structural[0].describe(document.path))} Nothing was changed. Fix that line by hand, or {_check_hint(document.path)}")


# Values in effect.


@dataclass(frozen=True)
class Setting:
    key: str
    value: object
    origin: str  # built-in, defaults, or profile NAME
    file: Optional[Path] = None
    line: Optional[int] = None
    value_lines: Tuple[int, ...] = ()

    def source(self) -> str:
        return self.origin if self.file is None else f"{self.origin}, {self.file.name} line {self.line}"

    def text(self) -> List[str]:
        return KEYS[self.key].text_of(self.value)


class Resolved:
    """The value in effect for every key, and where each came from."""

    def __init__(self, path: Optional[Path], profile: Optional[str], items: Dict[str, Setting]):
        self.path = path
        self.profile = profile
        self.items = items

    def __getitem__(self, key: str) -> Setting:
        return self.items[key]

    def value(self, key: str) -> object:
        return self.items[key].value

    @property
    def library(self) -> bool:
        return bool(self.value("library"))

    def files(self, key: str) -> List[Path]:
        """The paths of a path key, each checked to be a file, so a mistake names the settings line."""
        setting = self.items[key]
        for path, line in zip(setting.value, setting.value_lines):
            if not path.is_file():
                where = setting.file.name if setting.file else FILE_NAME
                raise UsageError(f"{key} in the {setting.origin} settings ({where} line {line}) names {path}, which is not a file")
        return list(setting.value)

    def exclude_items(self) -> List[Tuple[str, str]]:
        """Patterns from exclude-from files first, then exclude patterns, each with where it came from."""
        items: List[Tuple[str, str]] = []
        for path in self.files("exclude-from"):
            items.extend(scan.read_exclude_file(path))
        setting = self.items["exclude"]
        if setting.file is not None:
            items.extend((pattern, f"{setting.file.name} line {line}") for pattern, line in zip(setting.value, setting.value_lines))
        return items


def _no_profile(document: Document, name: str) -> UsageError:
    names = [found.name or "" for found in document.profiles()]
    if not names:
        return UsageError(
            f"there is no profile {name!r} in {document.path}, which has no profiles yet. Make one with: {self_command()} profile create {name}"
        )
    hint = _did_you_mean(name, names) or "."
    return UsageError(f"there is no profile {name!r} in {document.path}{hint} The profiles are: {', '.join(names)}")


def find_profile(document: Optional[Document], name: str, path: Path) -> Section:
    if document is None:
        raise UsageError(
            f"there is no settings file at {path}, so there is no profile {name!r}. Make one with: {self_command()} profile create {name}"
        )
    found = document.section("profile", name)
    if found is None:
        raise _no_profile(document, name)
    return found


def resolve(document: Optional[Document], profile: Optional[str], path: Optional[Path] = None) -> Resolved:
    items = {name: Setting(name, key.default, "built-in") for name, key in KEYS.items()}
    if document is not None:
        require_usable(document)
    if profile is not None:
        find_profile(document, profile, path or default_path())
    if document is None:
        return Resolved(None, None, items)
    layers = [document.section("defaults")] + ([document.section("profile", profile)] if profile is not None else [])
    for section in layers:
        for entry in section.entries if section else []:
            items[entry.key] = Setting(
                entry.key,
                document.values[(section.label, entry.key)],
                section.origin,
                document.path,
                entry.lines[0] + 1,
                tuple(index + 1 for index in entry.value_lines),
            )
    return Resolved(document.path, profile, items)


def settings_for(file: Optional[Path], profile: Optional[str], ignore: bool) -> Resolved:
    """What --settings, --profile and --no-settings choose. With no settings file, only built-in values."""
    if ignore:
        if profile is not None:
            raise UsageError("--profile cannot be used with --no-settings, which ignores every profile")
        return resolve(None, None)
    path = Path(file) if file is not None else default_path()
    return resolve(read_document(path, required=file is not None), profile, path)


# Changing the file. Each function returns the bytes of the whole new file.


def _with_ending(line: Tuple[str, str], newline: str) -> Tuple[str, str]:
    return line if line[1] else (line[0], newline)


def entry_lines(key: Key, values: Sequence[str]) -> List[str]:
    if not key.many:
        return [f"{key.name} = {values[0]}"]
    return [f"{key.name} ="] + [INDENT + value for value in values]


def _appended(document: Document, lines: List[Tuple[str, str]], header: str, body: Sequence[Tuple[str, str]]) -> bytes:
    newline = document.newline
    if lines:
        lines[-1] = _with_ending(lines[-1], newline)
        if lines[-1][0].strip():
            lines.append(("", newline))
    lines.append((header, newline))
    lines.extend(_with_ending(line, newline) for line in body)
    return document.render(lines)


def set_value(document: Document, section: Optional[Section], header: str, key: Key, values: Sequence[str]) -> bytes:
    """Replaces every line of the key in the section, keeping comments between them, or adds it at the end."""
    newline = document.newline
    new = [(text, newline) for text in entry_lines(key, values)]
    lines = list(document.lines)
    if section is None:
        return _appended(document, lines, header, new)
    found = section.find(key.name)
    if not found:
        at = section.last_line() + 1
        lines[at - 1] = _with_ending(lines[at - 1], newline)
        return document.render(lines[:at] + new + lines[at:])
    dropped = {index for entry in found for index in entry.lines}
    result: List[Tuple[str, str]] = []
    for index, line in enumerate(lines):
        if index == found[0].lines[0]:
            result.extend(new)
        if index not in dropped:
            result.append(line)
    return document.render(result)


def without_key(document: Document, section: Section, key: str) -> Optional[bytes]:
    """Removes the key's lines, keeping comments between them. None when the key is not there."""
    dropped = {index for entry in section.find(key) for index in entry.lines}
    if not dropped:
        return None
    return document.render([line for index, line in enumerate(document.lines) if index not in dropped])


def _is_comment(line: Tuple[str, str]) -> bool:
    stripped = line[0].strip()
    return bool(stripped) and stripped[0] in "#;"


def without_section(document: Document, section: Section) -> bytes:
    """Removes a section with the comments just above its header. Comments just above the next one stay."""
    lines = document.lines
    start = section.header
    while start > 0 and _is_comment(lines[start - 1]):
        start -= 1
    later = [found.header for found in document.sections if found.header > section.header]
    end = min(later) if later else len(lines)
    if later:
        while end - 1 > section.last_line() and _is_comment(lines[end - 1]):
            end -= 1
    kept = list(lines[:start])
    if not later:
        while kept and not kept[-1][0].strip():
            kept.pop()
    return document.render(kept + list(lines[end:]))


def renamed_section(document: Document, section: Section, name: str) -> bytes:
    lines = list(document.lines)
    lines[section.header] = (f"[profile {name}]", lines[section.header][1] or document.newline)
    return document.render(lines)


def with_section(document: Document, name: str, source: Optional[Section] = None) -> bytes:
    """Adds [profile NAME] at the end, empty or with a copy of another section's lines."""
    body = document.lines[source.header + 1 : source.last_line() + 1] if source else []
    return _appended(document, list(document.lines), f"[profile {name}]", body)


def save(path: Path, original: Optional[bytes], data: bytes) -> None:
    """Writes the whole file at once, unless it changed since it was read."""
    path = Path(path)
    try:
        with open(path, "rb") as handle:
            current: Optional[bytes] = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise UsageError(f"cannot read the settings file {path}: {exc.strerror or exc}") from None
    if current != original:
        raise UsageError(f"{path} changed while this command was changing it, so nothing was written. Run the command again")
    written = Document(path, data)
    before = Document(path, original) if original is not None else None
    if any(problem.structural for problem in written.problems) or written.section_problems() > (
        before.section_problems() if before else 0
    ):
        known = {problem.message for problem in before.problems} if before else set()
        new = [problem for problem in written.problems if problem.message not in known] or written.problems
        raise UsageError(f"that change would leave a problem: {_ended(new[0].describe(path))} Nothing was written")
    if path == default_path():
        home.ensure_home()
    sealing.write_new_file(Path(os.path.realpath(path)), data, force=True)
