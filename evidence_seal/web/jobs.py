"""Background jobs: sealing, stamping, verifying and comparing, each in a thread of its own.

The runner is bounded: at most ``MAX_ACTIVE`` jobs wait or run at once, and the newest ``MAX_KEPT``
finished jobs are remembered for this run only. Progress comes from the same meters the command
line uses. A job that hashes files can be cancelled: the meter stops it between chunks, and since
every file is written only once complete, nothing is left half written. A job that fails ends with
a plain message, never a stack trace.
"""

from __future__ import annotations

import secrets
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import scan
from ..console import size_text
from ..errors import EvidenceSealError
from ..text import printable

MAX_ACTIVE = 4
MAX_KEPT = 100
MAX_MESSAGES = 50
WAITING, RUNNING, DONE, FAILED, CANCELLED = "waiting", "running", "done", "failed", "cancelled"
FINISHED = (DONE, FAILED, CANCELLED)
CANCELLED_TEXT = "Cancelled. Files are written only once complete, so nothing was left half written, and nothing was recorded."
BUG_TEXT = (
    "this is a bug in evidence-seal, not a problem with your files ({name}). No result was reached."
    " Run the same step from the command line with EVIDENCE_SEAL_DEBUG=1 set for details."
)

Work = Callable[["Job"], Tuple[Dict[str, Any], Any]]


class Cancelled(Exception):
    """Raised inside a job's work when someone asked for it to stop."""


class TooManyJobs(EvidenceSealError):
    """Every job slot is taken. Nothing was started."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Job:
    def __init__(self, kind: str, title: str, seal: Optional[str], cancellable: bool):
        self.id = secrets.token_hex(16)
        self.kind = kind
        self.title = title
        self.seal = seal
        self.cancellable = cancellable
        self.state = WAITING
        self.created = _now()
        self.started: Optional[str] = None
        self.finished: Optional[str] = None
        self.verb = "Working"
        self.progress = {"files": 0, "total_files": 0, "bytes": 0, "total_bytes": 0}
        self.messages: List[str] = []
        self.error: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None
        self.payload: Any = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    def meter(self, verb: str) -> Callable[[scan.Meter], None]:
        """A progress report for ``scan.Meter`` that records progress and stops the work when cancelled."""
        self.verb = verb

        def report(meter: scan.Meter) -> None:
            with self._lock:
                self.progress = {
                    "files": meter.files,
                    "total_files": meter.total_files,
                    "bytes": meter.bytes,
                    "total_bytes": meter.total_bytes,
                }
            if self._cancel.is_set():
                raise Cancelled()

        return report

    def note(self, text: str) -> None:
        with self._lock:
            if len(self.messages) < MAX_MESSAGES:
                self.messages.append(printable(text))

    def request_cancel(self) -> bool:
        with self._lock:
            if not self.cancellable or self.state in FINISHED:
                return False
        self._cancel.set()
        return True

    @property
    def cancel_requested(self) -> bool:
        return self._cancel.is_set()

    def progress_text(self) -> str:
        with self._lock:
            state, progress = self.state, dict(self.progress)
        if state == WAITING:
            return "Waiting to start."
        if state != RUNNING:
            return {DONE: "Finished.", FAILED: "Stopped by a problem.", CANCELLED: "Cancelled."}[state]
        if not progress["total_files"]:
            return f"{self.verb}: starting."
        return (
            f"{self.verb} {progress['files']} of {progress['total_files']} files,"
            f" {size_text(progress['bytes'])} of {size_text(progress['total_bytes'])}."
        )

    def update(self, **values: Any) -> None:
        with self._lock:
            for name, value in values.items():
                setattr(self, name, value)

    def to_dict(self) -> Dict[str, Any]:
        text = self.progress_text()
        with self._lock:
            return {
                "id": self.id,
                "kind": self.kind,
                "title": self.title,
                "seal": self.seal,
                "state": self.state,
                "created": self.created,
                "started": self.started,
                "finished": self.finished,
                "cancellable": self.cancellable and self.state not in FINISHED,
                "cancel_requested": self._cancel.is_set(),
                "progress": dict(self.progress),
                "progress_text": text,
                "messages": list(self.messages),
                "error": self.error,
                "result": self.result,
            }


class JobRunner:
    def __init__(self, max_active: int = MAX_ACTIVE, max_kept: int = MAX_KEPT):
        self.max_active = max_active
        self.max_kept = max_kept
        self._jobs: "OrderedDict[str, Job]" = OrderedDict()
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, title: str, work: Work, seal: Optional[str] = None, cancellable: bool = False) -> Job:
        job = Job(kind, title, seal, cancellable)
        with self._lock:
            active = [item for item in self._jobs.values() if item.state not in FINISHED]
            if len(active) >= self.max_active:
                raise TooManyJobs(
                    f"{len(active)} jobs are already waiting or running, which is the most at once. Nothing was started."
                    " Try again when one has finished"
                )
            self._jobs[job.id] = job
            self._forget_old()
            thread = threading.Thread(target=self._run, args=(job, work), name=f"evidence-seal job {job.id}", daemon=True)
            self._threads[job.id] = thread
        thread.start()
        return job

    def _forget_old(self) -> None:
        finished = [key for key, item in self._jobs.items() if item.state in FINISHED]
        for key in finished[: max(0, len(self._jobs) - self.max_kept)]:
            del self._jobs[key]
            self._threads.pop(key, None)

    def _run(self, job: Job, work: Work) -> None:
        job.update(state=RUNNING, started=_now())
        final: Dict[str, Any] = {"state": FAILED}
        try:
            if job.cancel_requested:
                raise Cancelled()
            result, payload = work(job)
            final = {"state": DONE, "result": result, "payload": payload}
        except Cancelled:
            final["state"], final["error"] = CANCELLED, CANCELLED_TEXT
        except EvidenceSealError as exc:
            final["error"] = printable(str(exc))
        except OSError as exc:
            where = f"{exc.filename}: " if exc.filename else ""
            final["error"] = printable(f"{where}{exc.strerror or exc}. No result was reached.")
        except MemoryError:
            final["error"] = "this computer ran out of memory for this job. No result was reached."
        except Exception as exc:  # A bug must not look like a result, or show a stack trace
            final["error"] = BUG_TEXT.format(name=type(exc).__name__)
        finally:
            job.update(finished=_now(), **final)
            with self._lock:
                self._threads.pop(job.id, None)

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def jobs(self) -> List[Job]:
        """Newest first."""
        with self._lock:
            return list(reversed(self._jobs.values()))

    def latest(self, kind: str, seal: str) -> Optional[Job]:
        """The newest finished job of this kind for this seal that reached a result."""
        for job in self.jobs():
            if job.kind == kind and job.seal == seal and job.state == DONE:
                return job
        return None

    def stop(self, wait: float = 5.0) -> None:
        """Asks every job that can stop to stop, and waits a little for them."""
        with self._lock:
            jobs = list(self._jobs.values())
            threads = list(self._threads.values())
        for job in jobs:
            job.request_cancel()
        for thread in threads:
            thread.join(wait / max(1, len(threads)))
