"""Background jobs: their states, progress, cancellation, limits and plain failure messages."""

import threading
import time
import unittest

from evidence_seal import scan
from evidence_seal.errors import UsageError
from evidence_seal.web import jobs
from evidence_seal.web.jobs import JobRunner, TooManyJobs
from tests.web_support import WebTestCase


def finished(job, seconds=10):
    deadline = time.monotonic() + seconds
    while job.state not in jobs.FINISHED:
        if time.monotonic() > deadline:
            raise AssertionError(f"job did not finish: {job.to_dict()}")
        time.sleep(0.005)
    return job


class Blocked:
    """Work that reports progress, then waits until released, so a test can look at it while it runs."""

    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def __call__(self, job):
        report = job.meter("Hashed")
        meter = scan.Meter(report, 2, 100)
        meter.files, meter.bytes = 1, 40
        report(meter)
        self.started.set()
        while not self.release.wait(0.01):
            report(meter)
        return {"done": True}, "payload"


class Runner(unittest.TestCase):
    def setUp(self):
        self.runner = JobRunner(max_active=2, max_kept=3)
        self.addCleanup(self.runner.stop, 1)

    def test_a_job_runs_and_keeps_its_result(self):
        job = finished(self.runner.start("seal", "Seal", lambda job: ({"n": 1}, "kept")))
        self.assertEqual(job.state, jobs.DONE)
        self.assertEqual(job.result, {"n": 1})
        self.assertEqual(job.payload, "kept")
        data = job.to_dict()
        self.assertEqual(data["progress_text"], "Finished.")
        self.assertIsNotNone(data["started"])
        self.assertIsNotNone(data["finished"])
        self.assertNotIn("payload", data)
        self.assertIs(self.runner.get(job.id), job)

    def test_progress_is_reported_while_running(self):
        work = Blocked()
        job = self.runner.start("seal", "Seal", work, cancellable=True)
        self.assertTrue(work.started.wait(5))
        self.assertEqual(job.state, jobs.RUNNING)
        self.assertEqual(job.to_dict()["progress"]["files"], 1)
        self.assertIn("Hashed 1 of 2 files", job.progress_text())
        work.release.set()
        finished(job)

    def test_a_cancelled_job_says_so_and_has_no_result(self):
        work = Blocked()
        job = self.runner.start("verify", "Verify", work, cancellable=True)
        self.assertTrue(work.started.wait(5))
        self.assertTrue(job.request_cancel())
        finished(job)
        self.assertEqual(job.state, jobs.CANCELLED)
        self.assertIsNone(job.result)
        self.assertEqual(job.error, jobs.CANCELLED_TEXT)
        self.assertFalse(job.request_cancel())

    def test_a_job_that_cannot_be_stopped_safely_refuses_to_cancel(self):
        work = Blocked()
        job = self.runner.start("stamp", "Stamp", work, cancellable=False)
        self.assertTrue(work.started.wait(5))
        self.assertFalse(job.request_cancel())
        self.assertFalse(job.to_dict()["cancellable"])
        work.release.set()
        self.assertEqual(finished(job).state, jobs.DONE)

    def test_failures_are_plain_messages(self):
        def raises(error):
            def work(job):
                raise error
            return work

        cases = [
            (UsageError("the folder is gone"), "the folder is gone"),
            (FileNotFoundError(2, "No such file or directory", "C:\\x"), "No such file or directory"),
            (MemoryError(), "out of memory"),
            (ZeroDivisionError("secret detail"), "bug in evidence-seal"),
        ]
        for error, text in cases:
            with self.subTest(type(error).__name__):
                job = finished(self.runner.start("seal", "Seal", raises(error)))
                self.assertEqual(job.state, jobs.FAILED)
                self.assertIn(text, job.error)
                self.assertNotIn("Traceback", job.error)
                self.assertNotIn("secret detail", job.error)

    def test_jobs_are_bounded(self):
        blockers = [Blocked(), Blocked()]
        started = [self.runner.start("seal", "Seal", work) for work in blockers]
        with self.assertRaises(TooManyJobs):
            self.runner.start("seal", "Seal", Blocked())
        for work in blockers:
            work.release.set()
        for job in started:
            finished(job)
        for _ in range(5):
            finished(self.runner.start("seal", "Seal", lambda job: ({}, None)))
        self.assertLessEqual(len(self.runner.jobs()), 4)

    def test_latest_finds_the_newest_finished_job_for_a_seal(self):
        first = finished(self.runner.start("verify", "Verify", lambda job: ({"n": 1}, None), seal="a" * 64))
        second = finished(self.runner.start("verify", "Verify", lambda job: ({"n": 2}, None), seal="a" * 64))
        finished(self.runner.start("verify", "Verify", lambda job: ({"n": 3}, None), seal="b" * 64))
        self.assertIs(self.runner.latest("verify", "a" * 64), second)
        self.assertIsNot(first, second)
        self.assertIsNone(self.runner.latest("seal", "a" * 64))

    def test_messages_are_bounded_and_printable(self):
        job = self.runner.start("seal", "Seal", lambda job: ({}, None))
        for number in range(jobs.MAX_MESSAGES + 10):
            job.note(f"line\n{number}\x1b[31m")
        finished(job)
        self.assertEqual(len(job.messages), jobs.MAX_MESSAGES)
        self.assertNotIn("\n", job.messages[0])
        self.assertNotIn("\x1b", job.messages[0])


class ThroughTheServer(WebTestCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_cancel_from_the_page_and_the_api(self):
        for how in ("page", "api"):
            with self.subTest(how):
                work = Blocked()
                job = self.server.app.runner.start("verify", "Verify", work, cancellable=True)
                self.assertTrue(work.started.wait(5))
                page = self.get(f"/jobs/{job.id}").text
                self.assertIn(f'data-job="{job.id}"', page)
                self.assertIn("<progress", page)
                self.assertIn('http-equiv="refresh"', page)
                self.assertIn(f'action="/jobs/{job.id}/cancel"', page)
                if how == "page":
                    self.post(f"/jobs/{job.id}/cancel", {}, status=303)
                else:
                    self.api("POST", f"/jobs/{job.id}/cancel", status=200)
                finished(job)
                self.assertEqual(job.state, jobs.CANCELLED)
                page = self.get(f"/jobs/{job.id}").text
                self.assertIn("Cancelled", page)
                self.assertNotIn('http-equiv="refresh"', page)
                self.api("POST", f"/jobs/{job.id}/cancel", status=409)

    def test_too_many_jobs_is_a_plain_503(self):
        workers = []
        for _ in range(jobs.MAX_ACTIVE):
            work = Blocked()
            workers.append(work)
            self.server.app.runner.start("verify", "Verify", work)
        try:
            folder = self.make_folder("more")
            answer = self.api("POST", "/seal", {"folder": str(folder), "purpose": "Example Org"}, status=503)
            self.assertEqual(answer.json()["error"]["code"], "too_many_jobs")
            page = self.post("/new/seal", {"folder": str(folder), "purpose": "Example Org"}, status=503)
            self.assertIn("Nothing was started", page.text)
        finally:
            for work in workers:
                work.release.set()

    def test_a_failed_job_shows_a_message_and_no_trace(self):
        def broken(job):
            raise KeyError("internal name")

        job = finished(self.server.app.runner.start("seal", "Seal", broken))
        page = self.get(f"/jobs/{job.id}").text
        self.assertIn("bug in evidence-seal", page)
        self.assertNotIn("Traceback", page)
        self.assertNotIn("internal name", page)
        self.assertEqual(self.api("GET", f"/jobs/{job.id}", status=200).json()["job"]["state"], "failed")
        self.get(f"/jobs/{job.id}/report/text", status=409)

    def test_jobs_page_lists_jobs_newest_first(self):
        first = finished(self.server.app.runner.start("seal", "First <b>job</b>", lambda job: ({}, None)))
        second = finished(self.server.app.runner.start("seal", "Second job", lambda job: ({}, None)))
        text = self.get("/jobs").text
        self.assertLess(text.index(second.id), text.index(first.id))
        self.assertNotIn("<b>job", text)

    def test_a_cancelled_seal_writes_no_manifest(self):
        folder = self.make_folder("big", {f"file{number}.bin": b"x" * 1000 for number in range(30)})
        original = jobs.Job.meter

        def slow_meter(job, verb):
            report = original(job, verb)

            def slowed(meter):
                time.sleep(0.02)
                report(meter)

            return slowed

        from unittest import mock

        with mock.patch.object(jobs.Job, "meter", slow_meter):
            answer = self.api("POST", "/seal", {"folder": str(folder), "purpose": "Example Org"}, status=202)
            job_id = answer.json()["job"]["id"]
            self.api("POST", f"/jobs/{job_id}/cancel", status=200)
            job = self.wait_for(job_id)
        self.assertEqual(job["state"], "cancelled", job)
        self.assertEqual([path.name for path in self.temp.glob("big-manifest*")], [])
        self.assertEqual(self.api("GET", "/seals", status=200).json()["total"], 0)


if __name__ == "__main__":
    unittest.main()
