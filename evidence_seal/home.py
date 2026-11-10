"""Where evidence-seal keeps its own state: settings, the library of seals, and known authorities.

Everything lives in one folder so a user can find it, back it up or remove it in one place. The
EVIDENCE_SEAL_HOME environment variable moves it, which is also how the tests keep away from a
real user's folder. Sealed folders, manifests and tokens stay wherever the user put them.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping, Optional

ENVIRONMENT_VARIABLE = "EVIDENCE_SEAL_HOME"
FOLDER_NAME = "evidence-seal"


def home_dir(environ: Optional[Mapping[str, str]] = None) -> Path:
    """The folder for this tool's own files. It is not created here; whoever writes first creates it."""
    environ = os.environ if environ is None else environ
    chosen = environ.get(ENVIRONMENT_VARIABLE, "").strip()
    if chosen:
        return Path(chosen).expanduser()
    if sys.platform.startswith("win"):
        base = environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / FOLDER_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / FOLDER_NAME
    base = environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / FOLDER_NAME


def ensure_home(environ: Optional[Mapping[str, str]] = None) -> Path:
    """Creates the home folder if needed, readable only by this user where the system allows."""
    folder = home_dir(environ)
    folder.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(folder, 0o700)
        except OSError:
            pass
    return folder
