"""Runs the openssl command line for what pure Python here does not cover.

This module is the only place the package starts another program. Every result
says plainly whether openssl said yes, said no, or could not be run, and those
are never merged: a missing openssl is not a failed signature and not a pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from .der import epoch_seconds
from .x509 import Certificate

TIMEOUT_SECONDS = 120

YES = "yes"
NO = "no"
UNAVAILABLE = "unavailable"


@dataclass
class BridgeResult:
    answer: str
    command: str
    output: str = ""


def find_openssl() -> Optional[str]:
    return os.environ.get("EVIDENCE_SEAL_OPENSSL") or shutil.which("openssl")


def version() -> Optional[str]:
    program = find_openssl()
    if program is None:
        return None
    try:
        done = subprocess.run([program, "version"], capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except OSError:
        return None
    return done.stdout.decode("utf-8", "replace").strip() or None


def _major_version() -> int:
    text = version() or ""
    parts = text.split()
    if len(parts) >= 2 and parts[0] == "OpenSSL" and parts[1].split(".")[0].isdigit():
        return int(parts[1].split(".")[0])
    return 0


def _run(arguments: List[str], success_marker: str, cwd: Optional[Path] = None) -> BridgeResult:
    program = find_openssl()
    shown = "openssl " + " ".join(arguments[:2])
    if program is None:
        return BridgeResult(UNAVAILABLE, shown, "openssl was not found")
    try:
        done = subprocess.run(
            [program] + arguments,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
            cwd=str(cwd) if cwd else None,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return BridgeResult(UNAVAILABLE, shown, f"openssl could not be run: {exc}")
    output = (done.stdout + b"\n" + done.stderr).decode("utf-8", "replace").strip()
    if done.returncode == 0 and success_marker in output:
        return BridgeResult(YES, shown, output)
    lowered = output.lower()
    if "unknown option" in lowered or "invalid command" in lowered or "unrecognized" in lowered:
        return BridgeResult(UNAVAILABLE, shown, f"this openssl does not support the command: {output[:200]}")
    return BridgeResult(NO, shown, output)


def _write_pem(folder: Path, name: str, certificates: Sequence[Certificate]) -> Path:
    path = folder / name
    path.write_text("".join(cert.to_pem() for cert in certificates), encoding="ascii")
    return path


def _untrusted_argument(folder: Path, certificates: Sequence[Certificate]) -> str:
    """Openssl reads -untrusted as a list split on spaces and commas, so this is a bare name."""
    return _write_pem(folder, "untrusted.pem", certificates).name


def verify_signature_only(token_der: bytes, extra: Sequence[Certificate]) -> BridgeResult:
    """Checks the CMS signature and content digest, without looking at any chain."""
    with tempfile.TemporaryDirectory(prefix="evidence-seal-") as temp:
        folder = Path(temp)
        token = folder / "token.der"
        token.write_bytes(token_der)
        arguments = ["cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", str(token)]
        arguments += ["-out", str(folder / "content.bin")]
        if extra:
            arguments += ["-certfile", str(_write_pem(folder, "extra.pem", extra))]
        return _run(arguments, "Verification successful")


def verify_chain(
    signer: Certificate,
    untrusted: Sequence[Certificate],
    roots: Sequence[Certificate],
    at_time: datetime,
) -> BridgeResult:
    """Checks the chain with the timestamp-signing purpose at the token's time."""
    with tempfile.TemporaryDirectory(prefix="evidence-seal-") as temp:
        folder = Path(temp)
        arguments = ["verify", "-purpose", "timestampsign", "-attime", str(epoch_seconds(at_time))]
        # Without these, the verify command also trusts the system's default roots.
        arguments += ["-no-CApath"]
        if _major_version() >= 3:
            arguments += ["-no-CAstore"]
        arguments += ["-CAfile", str(_write_pem(folder, "roots.pem", roots))]
        if untrusted:
            arguments += ["-untrusted", _untrusted_argument(folder, untrusted)]
        arguments.append(str(_write_pem(folder, "signer.pem", [signer])))
        return _run(arguments, ": OK", folder)


def ts_verify(
    data_path: Path,
    token_path: Path,
    roots: Sequence[Certificate],
    untrusted: Sequence[Certificate],
    at_time: Optional[datetime],
    token_in: bool = False,
) -> BridgeResult:
    """The complete ``openssl ts -verify`` run, for a side by side comparison."""
    with tempfile.TemporaryDirectory(prefix="evidence-seal-") as temp:
        folder = Path(temp)
        arguments = ["ts", "-verify", "-data", str(Path(data_path).resolve()), "-in", str(Path(token_path).resolve())]
        if token_in:
            arguments.append("-token_in")
        arguments += ["-CAfile", str(_write_pem(folder, "roots.pem", roots))]
        if untrusted:
            arguments += ["-untrusted", _untrusted_argument(folder, untrusted)]
        if at_time is not None:
            arguments += ["-attime", str(epoch_seconds(at_time))]
        return _run(arguments, "Verification: OK", folder)
