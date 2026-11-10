"""The config and profile commands: see, check and change the settings file.

Registered through cli.COMMAND_MODULES. Every change goes through settings.save, which writes the
whole file at once, and only when nothing else changed the file after it was read.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import scan, settings
from .console import say, self_command
from .errors import UsageError
from .results import EXIT_FAILED, EXIT_VERIFIED
from .text import count_of

READ_EXITS = "exit codes: 0 done, 2 bad arguments, or a settings file that cannot be read or has a problem"
CHANGE_EXITS = (
    "exit codes: 0 done, 1 the file could not be written and was left as it was,"
    " 2 bad arguments or a settings file with a problem, and nothing was changed"
)
GROUP_EXITS = "exit codes: 0 done, 1 problems found or a file not written, 2 bad arguments or a settings file with a problem"
CHECK_EXITS = "exit codes: 0 no problems, 1 problems found, each one listed, 2 bad arguments or a file that cannot be read"

Handler = Callable[[argparse.Namespace], int]


def _parser(group, name: str, summary: str, description: str, epilog: str, run: Handler) -> argparse.ArgumentParser:
    parser = group.add_parser(name, help=summary, description=description, epilog=epilog, allow_abbrev=False)
    parser.add_argument(
        "--settings", dest="settings_file", type=Path, metavar="FILE", help="use this settings file instead of the usual one"
    )
    parser.set_defaults(run=run)
    return parser


def _profile_option(parser: argparse.ArgumentParser, what: str) -> None:
    parser.add_argument("--profile", metavar="NAME", help=f"{what} this profile instead of [defaults]")


def _json_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="print as JSON")


def register(commands) -> Dict[str, Handler]:
    config = commands.add_parser(
        "config",
        help="see, check or change the settings file",
        description="See, check or change the settings that fill in options for seal, stamp, verify and report.",
        epilog=f"Add --help after an action for its options. The file is described in docs/SETTINGS.md. {GROUP_EXITS}",
        allow_abbrev=False,
    )
    actions = config.add_subparsers(dest="config_action", required=True, metavar="ACTION")
    _parser(actions, "path", "say where the settings file is", "Print where the settings file is, and whether it exists.", READ_EXITS, _config_path)
    show = _parser(
        actions,
        "show",
        "print the value in effect for every setting, and where it came from",
        "Print the value in effect for every setting, and where it came from: a profile, [defaults], or built-in.",
        READ_EXITS,
        _config_show,
    )
    _profile_option(show, "as seen with")
    _json_option(show)
    get = _parser(actions, "get", "print the value in effect for one setting", "Print the value in effect for one setting, one line per item.", READ_EXITS, _config_get)
    get.add_argument("key", help="the setting, such as timeout")
    _profile_option(get, "as seen with")
    change = _parser(
        actions,
        "set",
        "set a value in the settings file",
        "Set a value in [defaults] or a profile. Every other line of the file stays exactly as it was.",
        CHANGE_EXITS,
        _config_set,
    )
    change.add_argument("key", help="the setting, such as timeout")
    change.add_argument("values", nargs="+", metavar="VALUE", help="the value; ca, untrusted, exclude and exclude-from take several")
    _profile_option(change, "set it in")
    unset = _parser(
        actions,
        "unset",
        "remove a value from the settings file",
        "Remove a value from [defaults] or a profile, so the next place in line applies.",
        CHANGE_EXITS,
        _config_unset,
    )
    unset.add_argument("key", help="the setting, such as timeout")
    _profile_option(unset, "remove it from")
    _parser(
        actions,
        "check",
        "list every problem in the settings file",
        "Read the settings file and list every problem, with its line. Also checks that named files exist.",
        CHECK_EXITS,
        _config_check,
    )

    profile = commands.add_parser(
        "profile",
        help="list, show, create, copy, rename or delete profiles",
        description="A profile is a named set of settings, chosen with --profile NAME on seal, stamp, verify and report.",
        epilog=f"Add --help after an action for its options. Change a profile's values with config set --profile NAME. {GROUP_EXITS}",
        allow_abbrev=False,
    )
    group = profile.add_subparsers(dest="profile_action", required=True, metavar="ACTION")
    listing = _parser(group, "list", "list the profiles", "List the profiles in the settings file.", READ_EXITS, _profile_list)
    _json_option(listing)
    showing = _parser(group, "show", "print what a profile sets", "Print the values a profile sets itself, with their lines.", READ_EXITS, _profile_show)
    showing.add_argument("name", help="the profile")
    _json_option(showing)
    create = _parser(group, "create", "add a profile", "Add a profile at the end of the settings file.", CHANGE_EXITS, _profile_create)
    create.add_argument("name", help="the new profile's name: letters, digits, hyphens, underscores and dots")
    create.add_argument("--from", dest="source", metavar="OTHER", help="start with a copy of this profile's lines")
    copy = _parser(group, "copy", "copy a profile under a new name", "Add a profile that starts as a copy of another.", CHANGE_EXITS, _profile_copy)
    copy.add_argument("name", metavar="OLD", help="the profile to copy")
    copy.add_argument("new", metavar="NEW", help="the new profile's name")
    rename = _parser(group, "rename", "rename a profile", "Rename a profile. Its lines and comments stay as they are.", CHANGE_EXITS, _profile_rename)
    rename.add_argument("name", metavar="OLD", help="the profile to rename")
    rename.add_argument("new", metavar="NEW", help="its new name")
    delete = _parser(
        group, "delete", "delete a profile", "Delete a profile, with the comments just above it.", CHANGE_EXITS, _profile_delete
    )
    delete.add_argument("name", help="the profile to delete")
    return {"config": _run, "profile": _run}


def _run(args: argparse.Namespace) -> int:
    return args.run(args)


# Reading.


def _path(args: argparse.Namespace) -> Path:
    return args.settings_file if args.settings_file is not None else settings.default_path()


def _usable(args: argparse.Namespace) -> Tuple[Path, Optional[settings.Document]]:
    path = _path(args)
    document = settings.read_document(path, required=args.settings_file is not None)
    if document is not None:
        settings.require_usable(document)
    return path, document


def _say_values(lines: Sequence[str], first: str, indent: str, note: str = "") -> None:
    shown = list(lines) or ["(none)"]
    say(f"{first}{shown[0]}{note}")
    for line in shown[1:]:
        say(f"{indent}{line}")


def _config_path(args: argparse.Namespace) -> int:
    path = _path(args)
    say(str(path))
    if path.is_file():
        say("It exists.")
    else:
        say(f"It does not exist yet, so every command uses built-in values. Setting a value creates it: {self_command()} config set KEY VALUE")
    return EXIT_VERIFIED


def _config_show(args: argparse.Namespace) -> int:
    path, document = _usable(args)
    resolved = settings.resolve(document, args.profile, path)
    if args.json:
        data = {
            "settings_file": str(path),
            "exists": document is not None,
            "profile": args.profile,
            "settings": {
                name: {
                    "value": settings.KEYS[name].json_of(setting.value),
                    "source": setting.origin,
                    "file": None if setting.file is None else str(setting.file),
                    "line": setting.line,
                }
                for name, setting in resolved.items.items()
            },
        }
        print(json.dumps(data, indent=2))
        return EXIT_VERIFIED
    say(f"Settings file: {path}" + ("" if document else " (it does not exist, so built-in values apply)"))
    say(f"Profile: {args.profile}" if args.profile else "Profile: none, so [defaults] apply, then built-in values")
    say()
    width = max(len(name) for name in settings.KEYS)
    for name, setting in resolved.items.items():
        _say_values(setting.text(), f"  {name:<{width}}  ", " " * (width + 4), f"  ({setting.source()})")
    return EXIT_VERIFIED


def _config_get(args: argparse.Namespace) -> int:
    key = settings.known_key(args.key)
    path, document = _usable(args)
    for line in settings.resolve(document, args.profile, path)[key.name].text():
        say(line)
    return EXIT_VERIFIED


def _reference_problems(document: settings.Document) -> List[settings.Problem]:
    """Named files that are missing or unreadable, and authority names that are not known."""
    found = []
    for section in document.sections:
        for entry in section.entries:
            if (section.label, entry.key) not in document.values:
                continue
            value = document.values[(section.label, entry.key)]
            where = f"{entry.key} in {section.label}"
            if settings.KEYS[entry.key].is_path:
                for path, index in zip(value, entry.value_lines):
                    if not path.is_file():
                        found.append(settings.Problem(index + 1, f"{where} names {path}, which is not a file", False))
                    elif entry.key == "exclude-from":
                        try:
                            scan.read_exclude_file(path)
                        except UsageError as exc:
                            found.append(settings.Problem(index + 1, f"{where}: {exc}", False))
            elif entry.key == "authority":
                try:
                    settings.resolve_authority(str(value))
                except UsageError as exc:
                    found.append(settings.Problem(entry.lines[0] + 1, f"{where}: {exc}", False))
    return found


def _config_check(args: argparse.Namespace) -> int:
    path = _path(args)
    document = settings.read_document(path, required=args.settings_file is not None)
    if document is None:
        say(f"There is no settings file at {path}, so every command uses built-in values.")
        return EXIT_VERIFIED
    problems = sorted(document.problems + _reference_problems(document), key=lambda problem: problem.line or 0)
    for problem in problems:
        say(problem.describe(path))
    if problems:
        say(f"{count_of(len(problems), 'problem')} in {path}. Nothing was changed.")
        return EXIT_FAILED
    say(f"No problems in {path}. It has {count_of(len(document.profiles()), 'profile')}.")
    return EXIT_VERIFIED


# Changing.


def _editable(args: argparse.Namespace) -> Tuple[Path, settings.Document, Optional[bytes]]:
    """The file and its bytes as read, or a new file's first lines and None when there is none yet."""
    path = _path(args)
    document = settings.read_document(path, required=False)
    if document is None:
        return path, settings.Document(path, settings.NEW_FILE_TEXT.encode("utf-8")), None
    settings.require_editable(document)
    return path, document, document.raw


def _target(
    document: settings.Document, original: Optional[bytes], profile: Optional[str], path: Path
) -> Tuple[Optional[settings.Section], str]:
    if profile is None:
        return document.section("defaults"), "[defaults]"
    return settings.find_profile(document if original is not None else None, profile, path), f"[profile {profile}]"


def _saved(path: Path, original: Optional[bytes], data: bytes) -> None:
    settings.save(path, original, data)
    if original is None:
        say(f"Created {path}.")


def _cleaned(key: settings.Key, given: Sequence[str]) -> List[str]:
    if not key.many and len(given) != 1:
        raise UsageError(f"{key.name} takes one value, not {len(given)}")
    values = []
    for item in given:
        value = item.strip()
        if not value:
            raise UsageError(f"a value for {key.name} cannot be empty")
        if settings.bad_character(value) is not None:
            raise UsageError(f"a value for {key.name} cannot hold line breaks or other control characters")
        if key.many and value[0] in "#;":
            raise UsageError(f"a value for {key.name} cannot start with {value[0]}, since the file would read it as a comment")
        if key.is_path:
            value = os.path.abspath(os.path.expanduser(value))
            if not os.path.isfile(value):
                raise UsageError(f"{value} is not a file, so {key.name} was not set")
        values.append(value)
    settings.check_given(key, values)
    return values


def _config_set(args: argparse.Namespace) -> int:
    key = settings.known_key(args.key)
    values = _cleaned(key, args.values)
    path, document, original = _editable(args)
    section, header = _target(document, original, args.profile, path)
    _saved(path, original, settings.set_value(document, section, header, key, values))
    _say_values(values, f"Set {key.name} in {header}: ", "  ")
    return EXIT_VERIFIED


def _config_unset(args: argparse.Namespace) -> int:
    path, document, original = _editable(args)
    if original is None:
        settings.known_key(args.key)
        say(f"There is no settings file at {path}, so {args.key} is not set there. Nothing was changed.")
        return EXIT_VERIFIED
    section, header = _target(document, original, args.profile, path)
    found = section.find(args.key) if section else []
    if not found:
        settings.known_key(args.key)
        say(f"{args.key} is not set in {header}, so nothing was changed.")
        return EXIT_VERIFIED
    data = settings.without_key(document, section, args.key)
    assert data is not None and section is not None
    settings.save(path, original, data)
    say(f"Removed {args.key} from {header} of {path}.")
    return EXIT_VERIFIED


def _new_name(document: settings.Document, name: str, path: Path) -> None:
    reason = settings.name_problem(name)
    if reason is not None:
        raise UsageError(f"the profile name {name!r} {reason}")
    if document.section("profile", name) is not None:
        raise UsageError(f"there is already a profile {name!r} in {path}")


def _create(args: argparse.Namespace, name: str, source_name: Optional[str]) -> int:
    path, document, original = _editable(args)
    _new_name(document, name, path)
    source = settings.find_profile(document if original is not None else None, source_name, path) if source_name else None
    _saved(path, original, settings.with_section(document, name, source))
    copied = f", a copy of {source_name}" if source_name else ""
    say(f"Added the profile {name} to {path}{copied}.")
    say(f"Change its values with: {self_command()} config set KEY VALUE --profile {name}")
    return EXIT_VERIFIED


def _profile_create(args: argparse.Namespace) -> int:
    return _create(args, args.name, args.source)


def _profile_copy(args: argparse.Namespace) -> int:
    return _create(args, args.new, args.name)


def _existing(args: argparse.Namespace) -> Tuple[Path, settings.Document, bytes, settings.Section]:
    path, document, original = _editable(args)
    section = settings.find_profile(document if original is not None else None, args.name, path)
    assert original is not None
    return path, document, original, section


def _profile_rename(args: argparse.Namespace) -> int:
    path, document, original, section = _existing(args)
    _new_name(document, args.new, path)
    settings.save(path, original, settings.renamed_section(document, section, args.new))
    say(f"Renamed the profile {args.name} to {args.new} in {path}.")
    return EXIT_VERIFIED


def _profile_delete(args: argparse.Namespace) -> int:
    path, document, original, section = _existing(args)
    settings.save(path, original, settings.without_section(document, section))
    say(f"Deleted the profile {args.name}, which set {count_of(len(section.entries), 'value')}, from {path}.")
    return EXIT_VERIFIED


# Profiles, read only.


def _profile_list(args: argparse.Namespace) -> int:
    path, document = _usable(args)
    profiles = document.profiles() if document else []
    if args.json:
        listed = [{"name": found.name, "line": found.header + 1, "keys": [entry.key for entry in found.entries]} for found in profiles]
        print(json.dumps({"settings_file": str(path), "profiles": listed}, indent=2))
        return EXIT_VERIFIED
    if not profiles:
        say(f"There are no profiles in {path}." if document else f"There is no settings file at {path}, so there are no profiles.")
        say(f"Make one with: {self_command()} profile create NAME")
        return EXIT_VERIFIED
    width = max(len(found.name or "") for found in profiles)
    for found in profiles:
        say(f"{found.name:<{width}}  {count_of(len(found.entries), 'value')}, line {found.header + 1}")
    return EXIT_VERIFIED


def _profile_show(args: argparse.Namespace) -> int:
    path, document = _usable(args)
    section = settings.find_profile(document, args.name, path)
    assert document is not None
    rows = [(entry, settings.KEYS[entry.key]) for entry in section.entries]
    if args.json:
        values = {
            entry.key: {"value": key.json_of(document.values[(section.label, entry.key)]), "line": entry.lines[0] + 1}
            for entry, key in rows
        }
        print(json.dumps({"settings_file": str(path), "name": args.name, "line": section.header + 1, "settings": values}, indent=2))
        return EXIT_VERIFIED
    say(f"{section.label} in {path}, line {section.header + 1}")
    if not rows:
        say("  It sets nothing, so [defaults] apply, then built-in values.")
    width = max([len(entry.key) for entry, _ in rows] + [0])
    for entry, key in rows:
        lines = key.text_of(document.values[(section.label, entry.key)])
        _say_values(lines, f"  {entry.key:<{width}}  ", " " * (width + 4), f"  (line {entry.lines[0] + 1})")
    return EXIT_VERIFIED
