"""The stamp command over a real socket, against a misbehaving authority on this machine.

Every server here listens on the loopback address only. Nothing leaves this computer.
"""

import hashlib
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from evidence_seal import stamping, tsp
from tests import forge
from tests.support import TempFolderTestCase, run_cli


class Authority(BaseHTTPRequestHandler):
    """Answers each request by calling the plan the test gave the server."""

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append(body)
        self.server.plan(self, body)

    def log_message(self, *_):
        pass

    def reply(self, status, body=b"", kind="application/timestamp-reply", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


FORGED = forge.Authority("network", seed=33)


def good_answer(handler, body, **options):
    parsed = tsp.parse_request(body)
    options.setdefault("nonce", parsed.nonce)
    options.setdefault("hash_oid", parsed.hash_oid)
    options.setdefault("data_hash", parsed.digest)
    handler.reply(200, FORGED.token(b"", **options))


class StampOverSockets(TempFolderTestCase):
    def setUp(self):
        super().setUp()
        self.manifest = self.write("m.txt", b"manifest bytes\n")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Authority)
        self.server.daemon_threads = True
        self.server.requests = []
        self.server.plan = good_answer
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/tsr"
        for patcher in (
            mock.patch.object(stamping, "_RETRY_DELAYS", (0.01, 0.01, 0.01)),
            mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def stamp(self, *extra):
        return run_cli("stamp", self.manifest, "--tsa-url", self.url, *extra)

    def saved(self):
        return sorted(path.name for path in self.temp.iterdir())

    def assert_failed_cleanly(self, plan, phrase, *extra):
        self.server.plan = plan
        code, out, err = self.stamp("--retries", "0", *extra)
        self.assertEqual(code, 1, err)
        self.assertIn(phrase, err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.saved(), ["m.txt"])
        self.assertEqual(self.manifest.read_bytes(), b"manifest bytes\n")

    def test_good_answer_round_trip_over_a_socket(self):
        code, out, err = self.stamp()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.saved(), ["m.ca.crt", "m.tsq", "m.tsr", "m.txt"])
        root = self.write("root.der", FORGED.root)
        code, text, _ = run_cli("verify", self.manifest, "--skip-files", "--ca", root, "--json")
        data = json.loads(text)
        self.assertEqual(code, 3)
        self.assertTrue(all(check["status"] == "pass" for check in data["token_checks"]), text)

    def test_rate_limit(self):
        self.assert_failed_cleanly(
            lambda h, _b: h.reply(429, b"slow down", "text/plain", [("Retry-After", "7")]),
            "limiting requests (HTTP 429). It asked for a wait of 7 seconds",
        )

    def test_rate_limit_is_waited_out_when_the_wait_is_short(self):
        calls = []

        def plan(handler, body):
            calls.append(1)
            if len(calls) == 1:
                handler.reply(429, b"", "text/plain", [("Retry-After", "1")])
            else:
                good_answer(handler, body)

        self.server.plan = plan
        started = time.monotonic()
        code, _, err = self.stamp()
        self.assertEqual(code, 0, err)
        self.assertGreaterEqual(time.monotonic() - started, 0.9)
        self.assertIn("Asking again in 1 seconds (1 of 2)", err)

    def test_a_wait_too_long_to_sit_through_is_reported(self):
        self.server.plan = lambda h, _b: h.reply(429, b"", "text/plain", [("Retry-After", "86400")])
        code, _, err = self.stamp()
        self.assertEqual(code, 1)
        self.assertIn("86400", err)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_outage_then_recovery(self):
        calls = []

        def plan(handler, body):
            calls.append(1)
            if len(calls) < 3:
                handler.reply(503, b"<html>down</html>", "text/html")
            else:
                good_answer(handler, body)

        self.server.plan = plan
        code, _, err = self.stamp()
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(len(set(self.server.requests)), 1, "a retry repeats the same request")
        self.assertIn("m.tsr", self.saved())

    def test_lasting_outage_stops_after_the_retries(self):
        self.server.plan = lambda h, _b: h.reply(503, b"down", "text/plain")
        code, _, err = self.stamp("--retries", "2")
        self.assertEqual(code, 1)
        self.assertEqual(len(self.server.requests), 3)
        self.assertIn("HTTP 503", err)
        self.assertIn("Nothing was saved", err)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_client_errors_are_not_retried(self):
        self.server.plan = lambda h, _b: h.reply(400, b"no", "text/plain")
        code, _, err = self.stamp("--retries", "5")
        self.assertEqual(code, 1)
        self.assertEqual(len(self.server.requests), 1)
        self.assertIn("HTTP 400", err)

    def test_web_page_with_status_200(self):
        self.assert_failed_cleanly(lambda h, _b: h.reply(200, b"<html>maintenance</html>", "text/html"), "web page")

    def test_garbage_with_status_200(self):
        self.assert_failed_cleanly(lambda h, _b: h.reply(200, b"\x30\x82garbage"), "not saved")

    def test_empty_answer(self):
        self.assert_failed_cleanly(lambda h, _b: h.reply(200), "empty answer")

    def test_answer_cut_off_midway(self):
        def plan(handler, _body):
            handler.send_response(200)
            handler.send_header("Content-Length", "5000")
            handler.end_headers()
            handler.wfile.write(b"\x30\x82\x13\x84")
            handler.wfile.flush()
            handler.close_connection = True

        self.assert_failed_cleanly(plan, "not saved")

    def test_connection_closed_with_no_answer(self):
        def plan(handler, _body):
            handler.close_connection = True

        self.assert_failed_cleanly(plan, "Nothing was saved")

    def test_not_http_at_all(self):
        def plan(handler, _body):
            handler.wfile.write(b"SSH-2.0-not-a-web-server\r\n\r\n")
            handler.close_connection = True

        self.assert_failed_cleanly(plan, "Nothing was saved")

    def test_answer_too_large(self):
        self.assert_failed_cleanly(lambda h, _b: h.reply(200, b"\0" * (tsp.MAX_TOKEN_BYTES + 10)), "larger than any real token")

    def test_redirect_is_not_followed(self):
        self.assert_failed_cleanly(
            lambda h, _b: h.reply(302, b"", "text/plain", [("Location", "http://127.0.0.1:9/elsewhere")]),
            "does not follow redirects",
        )
        self.assertEqual(len(self.server.requests), 1)

    def test_answer_that_never_finishes_hits_the_overall_limit(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def plan(handler, _body):
            handler.send_response(200)
            handler.send_header("Content-Length", "100000")
            handler.end_headers()
            while not release.wait(0.05):
                handler.wfile.write(b"\0")
                handler.wfile.flush()

        started = time.monotonic()
        self.assert_failed_cleanly(plan, "did not finish answering within 1 seconds", "--timeout", "1")
        self.assertLess(time.monotonic() - started, 10)

    def test_no_answer_at_all_times_out(self):
        release = threading.Event()
        self.addCleanup(release.set)
        self.assert_failed_cleanly(lambda _h, _b: release.wait(30), "Nothing was saved", "--timeout", "0.5")

    def test_network_down_is_plain(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        code, _, err = run_cli(
            "stamp", self.manifest, "--tsa-url", f"http://127.0.0.1:{closed_port}/tsr", "--retries", "1"
        )
        self.assertEqual(code, 1)
        self.assertIn("could not reach", err)
        self.assertIn("Asking again", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_wrong_nonce_bad_signature_and_other_data_leave_nothing(self):
        cases = (
            (lambda h, b: good_answer(h, b, nonce=5), "nonce"),
            (lambda h, b: good_answer(h, b, data_hash=b"\x01" * 32), "not saved"),
            (lambda h, b: good_answer(h, b, corrupt_signature=True), "Signature"),
            (lambda h, _b: h.reply(200, forge.rejection()), "request refused"),
        )
        for plan, phrase in cases:
            with self.subTest(phrase):
                self.assert_failed_cleanly(plan, phrase)

    def test_chain_that_fails_against_your_root_is_not_saved(self):
        other = forge.Authority("other", seed=44)
        root = self.write("other-root.der", other.root)
        self.server.plan = good_answer
        code, _, err = self.stamp("--ca", root)
        self.assertEqual(code, 1)
        self.assertIn("Certificate chain", err)
        self.assertNotIn("m.tsr", self.saved())

    def test_force_keeps_the_token_it_replaces(self):
        self.assertEqual(self.stamp()[0], 0)
        first = (self.temp / "m.tsr").read_bytes()
        code, out, err = self.stamp("--force")
        self.assertEqual(code, 0, err)
        self.assertNotEqual((self.temp / "m.tsr").read_bytes(), first)
        kept = [path for path in self.temp.iterdir() if ".replaced-" in path.name and path.suffix == ".tsr"]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_bytes(), first)
        self.assertIn("Kept the file this replaced", out)
        root = self.write("root.der", FORGED.root)
        code, text, _ = run_cli("verify", self.manifest, "--skip-files", "--ca", root, "--json")
        self.assertTrue(all(check["status"] == "pass" for check in json.loads(text)["token_checks"]), text)

    def test_a_second_token_checks_against_its_own_request(self):
        self.assertEqual(self.stamp()[0], 0)
        self.assertEqual(self.stamp("--out", self.temp / "second.tsr")[0], 0)
        root = self.write("root.der", FORGED.root)
        code, text, _ = run_cli(
            "verify", self.manifest, "--skip-files", "--ca", root, "--token", self.temp / "second.tsr", "--json"
        )
        self.assertTrue(all(check["status"] == "pass" for check in json.loads(text)["token_checks"]), text)

    def test_unrelated_file_named_like_the_request_is_kept(self):
        mine = self.write("m.tsq", b"something of mine")
        self.assertEqual(self.stamp()[0], 0)
        kept = [path for path in self.temp.iterdir() if ".replaced-" in path.name and path.suffix == ".tsq"]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_bytes(), b"something of mine")
        self.assertNotEqual(mine.read_bytes(), b"something of mine")

    def test_kept_copies_inside_a_sealed_folder_are_not_added_files(self):
        folder = self.temp / "work"
        folder.mkdir()
        self.write("work/a.txt", b"a\n")
        out = folder / "seal.txt"
        self.assertEqual(run_cli("seal", folder, "--purpose", "p", "--out", out)[0], 0)
        self.manifest = out
        self.assertEqual(self.stamp()[0], 0)
        self.assertEqual(self.stamp("--force")[0], 0)
        root = self.write("root.der", FORGED.root)
        code, text, _ = run_cli("verify", out, "--ca", root, "--json")
        data = json.loads(text)
        self.assertEqual(data["differences"]["added"], [], text)
        self.assertEqual(code, 0, text)

    def test_kept_copies_beside_a_hand_made_list_are_named_not_added(self):
        folder = self.temp / "work"
        folder.mkdir()
        self.write("work/a.txt", b"a\n")
        self.manifest = self.write("work/list.txt", hashlib.sha256(b"a\n").hexdigest().encode() + b"  a.txt\n")
        self.assertEqual(self.stamp()[0], 0)
        self.assertEqual(self.stamp("--force")[0], 0)
        root = self.write("root.der", FORGED.root)
        code, text, _ = run_cli("verify", self.manifest, "--ca", root, "--json")
        data = json.loads(text)
        self.assertEqual(data["differences"]["added"], [], text)
        self.assertEqual(code, 0, text)
        self.assertTrue(any(".replaced-" in name for name in data["differences"]["own_files_not_compared"]))

    def test_names_that_would_overwrite_the_manifest_are_refused(self):
        for name, extra in (("m.tsr", ()), ("m.tsq", ()), ("n.txt", ("--out", "n.txt"))):
            with self.subTest(name):
                target = self.write(name, b"precious\n")
                options = [str(self.temp / item) if item == "n.txt" else item for item in extra]
                code, _, err = run_cli("stamp", target, "--tsa-url", self.url, "--force", *options)
                self.assertEqual(code, 2, err)
                self.assertIn("overwrite", err)
                self.assertEqual(target.read_bytes(), b"precious\n")
        self.assertEqual(self.server.requests, [])

    def test_damaged_native_manifest_is_never_sent(self):
        self.write("sealme/a.txt", b"a\n")
        out = self.temp / "n.txt"
        self.assertEqual(run_cli("seal", self.temp / "sealme", "--purpose", "p", "--out", out)[0], 0)
        out.write_bytes(out.read_bytes().replace(b"files: 1", b"files: 2"))
        code, _, err = run_cli("stamp", out, "--tsa-url", self.url)
        self.assertEqual(code, 2)
        self.assertIn("damaged", err)
        self.assertEqual(self.server.requests, [])

    def test_bad_urls_and_settings_are_usage_errors(self):
        for url in ("http://", "not a url", "http://[bad/tsr", "file:///etc/hosts", "http://exa mple/tsr"):
            with self.subTest(url):
                code, _, err = run_cli("stamp", self.manifest, "--tsa-url", url)
                self.assertEqual(code, 2, err)
                self.assertNotIn("Traceback", err)
        for extra in (("--timeout", "-1"), ("--timeout", "soon"), ("--retries", "many"), ("--policy", "abc"), ("--policy", "9.9")):
            with self.subTest(extra):
                self.assertEqual(self.stamp(*extra)[0], 2)
        self.assertEqual(self.server.requests, [])

    def test_only_a_hash_leaves_the_machine(self):
        self.assertEqual(self.stamp()[0], 0)
        self.assertNotIn(b"manifest bytes", self.server.requests[0])
        self.assertLess(len(self.server.requests[0]), 200)
