"""The ``serve`` command, registered through cli.COMMAND_MODULES.

Public API: register(commands), as cli.COMMAND_MODULES expects.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from typing import Callable, Dict

from .. import settings
from ..authority_commands import _port
from ..console import say
from ..results import EXIT_INTERRUPTED, EXIT_VERIFIED
from .server import WebServer

KEY_WARNING = (
    "The address carries this run's access key: anyone with it can use the interface while serve runs."
    " Do not share it. A new key is made each time serve starts."
)


def register(commands) -> Dict[str, Callable[[argparse.Namespace], int]]:
    serve = commands.add_parser(
        "serve",
        help="open a web interface to the seal library on this computer",
        description=(
            "Serve a web interface and JSON API on this computer only: browse and search sealed folders,"
            " verify them, seal and stamp new ones, check files you were given, and compare seals."
            " It listens on a loopback address, and every request needs this run's access key."
            " Stamping is the only step that uses the network. See docs/WEB.md."
        ),
        epilog="exit codes: 0 stopped, 2 bad arguments or the port cannot be used, 130 stopped by Ctrl+C",
        allow_abbrev=False,
    )
    serve.add_argument("--port", type=_port, default=0, help="port to listen on (default: a free port the system chooses)")
    serve.add_argument("--host", default="127.0.0.1", help="loopback address to listen on (default: %(default)s)")
    serve.add_argument("--open", action="store_true", help="open the address in the web browser once listening")
    serve.add_argument("--profile", metavar="NAME", help="settings profile that seal, stamp and check use unless a form chooses another")
    return {"serve": _serve}


def _serve(args: argparse.Namespace) -> int:
    if args.profile is not None:
        settings.settings_for(None, args.profile, False)  # A missing profile is a usage error now, not on the first form
    server = WebServer(args.host, args.port, args.profile).bind()
    say(f"The evidence-seal web interface is answering at {server.url}")
    say(f"Open: {server.address}")
    say(KEY_WARNING)
    say("Only this computer can reach it. Press Ctrl+C to stop.")
    sys.stdout.flush()
    if args.open:
        try:
            if not webbrowser.open(server.address):
                say("Could not open a web browser; open the address above yourself.")
        except webbrowser.Error:
            say("Could not open a web browser; open the address above yourself.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        say("Stopped the web interface. Unfinished jobs were cancelled where that was safe.")
        return EXIT_INTERRUPTED
    return EXIT_VERIFIED
