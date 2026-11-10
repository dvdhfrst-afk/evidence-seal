"""The authority and test-authority commands.

``authority`` shows and changes the authority list (authorities.py). ``test-authority`` makes,
describes and serves the local test authority (local_authority.py and local_server.py).

Public API: register(commands), as cli.COMMAND_MODULES expects.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List

from . import authorities, local_authority, sealing
from .console import say, self_command, shown, warn
from .errors import UsageError
from .local_server import LocalServer, ServeOptions
from .results import EXIT_FAILED, EXIT_INTERRUPTED, EXIT_VERIFIED
from .x509 import Certificate

LIST_EXIT_CODES = "exit codes: 0 done, 2 bad arguments or an unreadable authority list"
CHANGE_EXIT_CODES = "exit codes: 0 changed, 2 bad arguments or an unreadable file, and nothing was changed"
TEST_ONLY = "Tokens from a test authority prove nothing to anyone else: whoever holds its key file can sign any date."


def _parser(group, name: str, summary: str, description: str, epilog: str) -> argparse.ArgumentParser:
    return group.add_parser(name, help=summary, description=description, epilog=epilog, allow_abbrev=False)


def _whole(text: str, low: int, high: int, what: str) -> int:
    if not text.isascii() or not text.isdigit() or len(text) > 7 or not low <= int(text) <= high:
        raise argparse.ArgumentTypeError(f"must be {what} from {low} to {high}")
    return int(text)


def _days(text: str) -> int:
    return _whole(text, 1, local_authority.MAX_DAYS, "a whole number of days")


def _port(text: str) -> int:
    return _whole(text, 0, 65535, "a port number")


def _busy(text: str) -> int:
    return _whole(text, 0, 1000, "a whole number")


def _delay(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from None
    if not 0 <= value <= 300:
        raise argparse.ArgumentTypeError("must be from 0 to 300 seconds")
    return value


def _moment(text: str) -> datetime:
    value = text.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a time such as 2026-03-01T12:00:00Z") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def register(commands) -> Dict[str, Callable[[argparse.Namespace], int]]:
    authority = _parser(
        commands,
        "authority",
        "list, add and remove timestamp authorities, and the roots trusted for them",
        "Keep a list of timestamp authorities, so stamp --authority NAME can use one by name. The roots"
        " in this list are trusted by verify and report.",
        "Run an action with --help for its options. " + CHANGE_EXIT_CODES,
    )
    actions = authority.add_subparsers(dest="authority_action", required=True, metavar="ACTION")

    listing = _parser(actions, "list", "show every authority in the list", "Show every authority in the list.", LIST_EXIT_CODES)
    listing.add_argument("--json", action="store_true", help="print as JSON")
    listing.set_defaults(action=_list)

    show = _parser(actions, "show", "show one authority and its roots", "Show one authority: its URL, roots and policy.", LIST_EXIT_CODES)
    show.add_argument("name", help="the authority's name")
    show.add_argument("--json", action="store_true", help="print as JSON")
    show.set_defaults(action=_show)

    add = _parser(
        actions,
        "add",
        "add an authority to the list",
        "Add an authority. Check each root's fingerprint against one the authority publishes, through a"
        " channel you trust, before you add it: every token that chains to it will then verify.",
        CHANGE_EXIT_CODES,
    )
    add.add_argument("name", help="a short name: letters, digits, dots, hyphens and underscores")
    add.add_argument("url", help="the authority's RFC 3161 URL")
    add.add_argument("--root", type=Path, action="append", default=[], metavar="FILE", help="trust this root certificate file for it; can repeat")
    add.add_argument("--policy", help="ask for this policy OID (object identifier) when stamping")
    add.add_argument("--hash", default="sha256", dest="hash_name", help="sha256, sha384 or sha512 (default: %(default)s)")
    add.add_argument("--note", default="", help="a note for yourself, such as where its terms are")
    add.set_defaults(action=_add)

    remove = _parser(actions, "remove", "remove an authority you added", "Remove an authority you added. Built-in ones stay.", CHANGE_EXIT_CODES)
    remove.add_argument("name", help="the authority's name")
    remove.set_defaults(action=_remove)

    trust = _parser(actions, "trust", "trust another root for an authority", "Trust the roots in a certificate file for an authority you added.", CHANGE_EXIT_CODES)
    trust.add_argument("name", help="the authority's name")
    trust.add_argument("--root", type=Path, required=True, metavar="FILE", help="the root certificate file")
    trust.set_defaults(action=_trust)

    untrust = _parser(actions, "untrust", "stop trusting one root of an authority", "Stop trusting one root of an authority you added.", CHANGE_EXIT_CODES)
    untrust.add_argument("name", help="the authority's name")
    untrust.add_argument("fingerprint", help="the root's SHA-256 fingerprint, as authority show prints it")
    untrust.set_defaults(action=_untrust)

    root = _parser(
        actions,
        "root",
        "write the stored root certificates of an authority",
        "Write the stored copies of an authority's root certificates, in PEM form.",
        "exit codes: 0 written, 1 no copy is stored, 2 bad arguments",
    )
    root.add_argument("name", help="the authority's name")
    root.add_argument("--out", type=Path, help="write to this file (default: standard output)")
    root.add_argument("--force", action="store_true", help="replace an existing file")
    root.set_defaults(action=_root)

    test = _parser(
        commands,
        "test-authority",
        "a timestamp authority on this computer, for trying the tool; its tokens prove nothing",
        "Make and run a local test authority, for trying the tool and testing offline. " + TEST_ONLY,
        "Run an action with --help for its options. exit codes: 0 done, 2 bad arguments, 130 stopped by Ctrl+C",
    )
    test_actions = test.add_subparsers(dest="test_action", required=True, metavar="ACTION")
    init = _parser(
        test_actions,
        "init",
        "make a new test authority",
        "Make a fresh root, a timestamping certificate and its key, and list the root as local-test. " + TEST_ONLY,
        "exit codes: 0 made, 2 bad arguments or the folder is in use, and nothing was changed",
    )
    init.add_argument("folder", type=Path, nargs="?", help="where to keep it (default: test-authority in the home folder)")
    init.add_argument("--name", default="local", help="a name for its certificates (default: %(default)s)")
    init.add_argument("--days", type=_days, default=365, metavar="N", help="days its certificates are valid (default: %(default)s)")
    init.add_argument("--force", action="store_true", help="replace a test authority already there, and its list entry")
    init.add_argument("--no-register", action="store_true", help="do not add it to the authority list")
    init.set_defaults(action=_init)

    serve = _parser(
        test_actions,
        "serve",
        "answer RFC 3161 requests on this computer",
        "Answer RFC 3161 requests over HTTP, on a loopback address only, until Ctrl+C. " + TEST_ONLY,
        "exit codes: 2 bad arguments or the port is in use, 130 stopped by Ctrl+C",
    )
    serve.add_argument("folder", type=Path, nargs="?", help="the test authority's folder (default: the one init makes)")
    serve.add_argument("--port", type=_port, default=local_authority.DEFAULT_PORT, help="port to listen on, 0 for any free one (default: %(default)s)")
    serve.add_argument("--host", default="127.0.0.1", help="loopback address to listen on (default: %(default)s)")
    serve.add_argument("--refuse", action="store_true", help="refuse every request, with a rejection status")
    serve.add_argument("--busy", type=_busy, default=0, metavar="N", help="answer the first N requests with HTTP 429 and Retry-After")
    serve.add_argument("--delay", type=_delay, default=0.0, metavar="SECONDS", help="wait this long before each answer")
    serve.add_argument("--time", type=_moment, metavar="ISO", help="sign this time instead of now, such as 2026-03-01T12:00:00Z")
    serve.add_argument("--broken", action="store_true", help="answer bytes that are not a token")
    serve.set_defaults(action=_serve)

    info = _parser(
        test_actions,
        "info",
        "show a test authority's root, policy and URL",
        "Show a test authority's root fingerprint, validity, policy and the URL to use.",
        "exit codes: 0 shown, 2 no test authority there",
    )
    info.add_argument("folder", type=Path, nargs="?", help="the test authority's folder (default: the one init makes)")
    info.set_defaults(action=_info)
    return {"authority": _run, "test-authority": _run}


def _run(args: argparse.Namespace) -> int:
    return args.action(args)


# authority


def _kind(entry: authorities.Entry) -> str:
    if entry.builtin:
        return "built in"
    if entry.test:
        return f"test authority, added {entry.added}"
    return f"added {entry.added}"


def _list(args: argparse.Namespace) -> int:
    entries = authorities.all_entries()
    if args.json:
        print(json.dumps({"schema_version": 1, "authorities": [entry.to_dict() for entry in entries]}, indent=2))
        return EXIT_VERIFIED
    width = max((len(entry.name) for entry in entries), default=0)
    for entry in entries:
        roots = len(entry.roots)
        say(f"{entry.name.ljust(width)}  {entry.url}  ({_kind(entry)}, {roots} root{'s' if roots != 1 else ''})")
    say(f"Details: {self_command()} authority show NAME")
    return EXIT_VERIFIED


def _entry(name: str) -> authorities.Entry:
    entry = authorities.find(name)
    if entry is None:
        raise UsageError(f"there is no authority named {name!r} in the list. See the names with: authority list")
    return entry


def _root_lines(entry: authorities.Entry) -> List[str]:
    lines = []
    for root in entry.roots:
        lines.append(f"  SHA-256 {root.sha256}")
        cert = root.certificate
        if cert is None:
            lines.append("    built in by fingerprint only; no copy is stored")
        else:
            lines.append(f"    {cert.subject.display()}")
            lines.append(f"    valid {cert.not_before:%Y-%m-%d} to {cert.not_after:%Y-%m-%d}")
    return lines


def _show(args: argparse.Namespace) -> int:
    entry = _entry(args.name)
    if args.json:
        print(json.dumps(entry.to_dict(), indent=2))
        return EXIT_VERIFIED
    say(f"Name: {entry.name} ({_kind(entry)})")
    say(f"URL: {entry.url}")
    say(f"Policy: {entry.policy or 'the authority chooses'}")
    say(f"Hash: {entry.hash_name}")
    if entry.terms_url:
        say(f"Terms of use: {entry.terms_url}")
    if entry.root_url:
        say(f"Root published at: {entry.root_url}")
    if entry.note:
        say(f"Note: {entry.note}")
    say(f"Roots trusted for it ({len(entry.roots)}):")
    for line in _root_lines(entry) or ["  none, so stamp --authority refuses it until you add one with authority trust"]:
        say(line)
    if entry.test:
        say(f"This is a local test authority. {TEST_ONLY}")
    return EXIT_VERIFIED


def _add(args: argparse.Namespace) -> int:
    entry = authorities.add(args.name, args.url, args.root, args.policy, args.hash_name, args.note)
    say(f"Added {entry.name}: {entry.url}")
    if entry.roots:
        say("Every token that chains to these roots now verifies, so check each fingerprint against one the")
        say("authority publishes, through a channel you trust:")
        for line in _root_lines(entry):
            say(line)
    else:
        say(f"No root is trusted for it yet, so stamp --authority {entry.name} refuses it. Add one with:")
        say(f"  {self_command()} authority trust {entry.name} --root FILE")
    say("Stamp with it:")
    say(f"  {self_command()} stamp MANIFEST --authority {entry.name}")
    return EXIT_VERIFIED


def _remove(args: argparse.Namespace) -> int:
    entry = authorities.remove(args.name)
    say(f"Removed {entry.name}. Its roots are no longer trusted by default; tokens it issued still verify with --ca.")
    return EXIT_VERIFIED


def _trust(args: argparse.Namespace) -> int:
    entry, added = authorities.trust_root(args.name, args.root)
    if not added:
        say(f"{entry.name} already trusts every root in {args.root}. Nothing was changed.")
        return EXIT_VERIFIED
    say(f"{entry.name} now trusts:")
    for root in added:
        say(f"  SHA-256 {root.sha256}  {root.certificate.subject.display()}")
    say("Check each fingerprint against one the authority publishes, through a channel you trust.")
    return EXIT_VERIFIED


def _untrust(args: argparse.Namespace) -> int:
    entry = authorities.untrust_root(args.name, args.fingerprint)
    left = len(entry.roots)
    say(f"{entry.name} no longer trusts that root. It has {left} root{'s' if left != 1 else ''} left.")
    return EXIT_VERIFIED


def _root(args: argparse.Namespace) -> int:
    entry = _entry(args.name)
    stored = [root.certificate for root in entry.roots if root.certificate is not None]
    if not stored:
        where = f" Get it from {entry.root_url} and" if entry.root_url else " Get it from the authority and"
        fingerprints = ", ".join(root.sha256 for root in entry.roots) or "none"
        warn(f"No copy of a root is stored for {entry.name}.{where} check that its SHA-256 fingerprint is: {fingerprints}")
        return EXIT_FAILED
    pem = "".join(cert.to_pem() for cert in stored)
    if args.out is None:
        sys.stdout.write(pem)
        return EXIT_VERIFIED
    sealing.write_new_file(args.out, pem.encode("ascii"), force=args.force)
    say(f"Wrote {len(stored)} root certificate{'s' if len(stored) != 1 else ''} of {entry.name} to {args.out}")
    return EXIT_VERIFIED


# test-authority


def _describe(authority: local_authority.LocalAuthority) -> None:
    root: Certificate = authority.root
    say(f"Folder: {authority.folder}")
    say(f"Root: {root.subject.display()}")
    say(f"  SHA-256 {root.sha256}")
    say(f"  valid {root.not_before:%Y-%m-%d %H:%M} to {root.not_after:%Y-%m-%d %H:%M} UTC")
    say(f"Policy: {authority.policy}")
    say(f"Key file: {authority.folder / local_authority.KEY_FILE} (TEST ONLY)")


def _registered(authority: local_authority.LocalAuthority) -> bool:
    entry = authorities.entry_for_root(authority.root.sha256)
    return entry is not None and entry.test


def _init(args: argparse.Namespace) -> int:
    result = local_authority.init(args.folder, args.name, args.days, args.force, not args.no_register)
    say(("Replaced the test authority." if result.replaced else "Made a test authority.") + f" {TEST_ONLY}")
    _describe(result.authority)
    folder = "" if args.folder is None else f" {shown(result.authority.folder)}"
    if result.entry is not None:
        say(f"Listed as {result.entry.name}, so verify and report trust its tokens on this computer.")
    say("Next, start it, and in another window stamp a manifest with it:")
    say(f"  {self_command()} test-authority serve{folder}")
    if result.entry is not None:
        say(f"  {self_command()} stamp MANIFEST --authority {result.entry.name}")
    else:
        say(f"  {self_command()} stamp MANIFEST --tsa-url {local_authority.default_url()} --ca {shown(result.authority.folder / local_authority.ROOT_FILE)}")
    return EXIT_VERIFIED


def _info(args: argparse.Namespace) -> int:
    authority = local_authority.load(args.folder)
    say(f"Local test authority {authority.name}, made {authority.created}. {TEST_ONLY}")
    _describe(authority)
    say(f"URL when served: {local_authority.default_url()}")
    if _registered(authority):
        say(f"Listed as {local_authority.REGISTERED_NAME}: stamp --authority {local_authority.REGISTERED_NAME} uses it.")
    else:
        say("Not in the authority list, so verify needs --ca with its root.crt to trust its tokens.")
    return EXIT_VERIFIED


def _log(text: str) -> None:
    warn(f"{datetime.now():%H:%M:%S} {text}")


def _serve(args: argparse.Namespace) -> int:
    authority = local_authority.load(args.folder)
    options = ServeOptions(args.refuse, args.busy, args.delay, args.time, args.broken)
    server = LocalServer(authority, args.host, args.port, options, _log).bind()
    say(f"Test authority {authority.name} (TEST ONLY) is answering at {server.url}")
    say(TEST_ONLY)
    if _registered(authority) and server.url == local_authority.default_url():
        say(f"Stamp with: {self_command()} stamp MANIFEST --authority {local_authority.REGISTERED_NAME}")
    else:
        say(f"Stamp with: {self_command()} stamp MANIFEST --tsa-url {server.url}")
    switches = [name for name, on in (("--refuse", args.refuse), ("--broken", args.broken)) if on]
    if args.busy:
        switches.append(f"--busy {args.busy}")
    if args.delay:
        switches.append(f"--delay {args.delay:g}")
    if args.time:
        switches.append(f"--time {args.time:%Y-%m-%dT%H:%M:%SZ}")
    if switches:
        say("Misbehaving on purpose: " + ", ".join(switches))
    say("Press Ctrl+C to stop.")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        say("Stopped the test authority.")
        return EXIT_INTERRUPTED
    return EXIT_VERIFIED
