"""The local test authority: init, info, the server and every switch, and a whole offline run.

Every server here listens on the loopback address only. Nothing leaves this computer.
"""

import http.client
import json
import os
import socket
import stat
import subprocess
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from evidence_seal import authorities, hashes, local_authority, local_server, stamping, tsp, verification
from evidence_seal.errors import UsageError
from evidence_seal.local_server import LocalServer, ServeOptions
from evidence_seal.openssl_bridge import YES, ts_verify
from evidence_seal.x509 import Certificate, load_certificates
from tests.support import ROOT_OF_REPO, HomeTestCase, requires_openssl, run_cli

DATA = b"a manifest stamped by the local test authority\n"


def request(data=DATA, **options):
    algorithm = options.pop("algorithm", hashes.SHA256)
    options.setdefault("nonce", 12345)
    return tsp.build_request(algorithm, options.pop("digest", algorithm.digest(data)), **options)


class TestAuthorityCase(HomeTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(stamping, "_RETRY_DELAYS", (0.01, 0.01, 0.01))
        patcher.start()
        self.addCleanup(patcher.stop)

    def make(self, *extra):
        code, out, err = run_cli("test-authority", "init", *extra)
        self.assertEqual(code, 0, err)
        return out

    def serve(self, folder=None, **options):
        server = LocalServer(local_authority.load(folder), options=ServeOptions(**options)).start()
        self.addCleanup(server.stop)
        return server

    def manifest(self):
        self.write("work/a.txt", b"first file\n")
        path = self.temp / "work-manifest.txt"
        code, _, err = run_cli("seal", self.temp / "work", "--purpose", "trying the test authority", "--out", path)
        self.assertEqual(code, 0, err)
        return path


class Init(TestAuthorityCase):
    def test_init_makes_its_files_and_lists_itself(self):
        out = self.make()
        folder = self.home / "test-authority"
        self.assertEqual(
            sorted(path.name for path in folder.iterdir()),
            ["TEST-ONLY-signer-key.pem", "authority.json", "root.crt", "signer.crt"],
        )
        self.assertIn("prove nothing to anyone else", out)
        self.assertIn("stamp MANIFEST --authority local-test", out)
        key = (folder / "TEST-ONLY-signer-key.pem").read_bytes()
        self.assertTrue(key.startswith(b"TEST ONLY."))
        root = load_certificates(folder / "root.crt")[0]
        signer = load_certificates(folder / "signer.crt")[0]
        for cert in (root, signer):
            self.assertIn("TEST ONLY", cert.subject.display())
        self.assertEqual(signer.extended_key_usage(), ["1.3.6.1.5.5.7.3.8"])
        entry = authorities.find("local-test")
        self.assertTrue(entry.test)
        self.assertEqual(entry.roots[0].sha256, root.sha256)
        self.assertEqual(entry.url, "http://127.0.0.1:3161/tsr")
        policy = json.loads((folder / "authority.json").read_text(encoding="utf-8"))["policy"]
        self.assertRegex(policy, r"^2\.25\.\d+$")
        self.assertEqual(entry.policy, policy)

    @unittest.skipIf(os.name == "nt", "Windows has no permission bits; the home folder's ACL keeps the key private")
    def test_the_key_is_readable_only_by_this_user(self):
        self.make()
        mode = stat.S_IMODE(os.stat(self.home / "test-authority" / "TEST-ONLY-signer-key.pem").st_mode)
        self.assertEqual(mode, 0o600)

    def test_each_init_is_a_fresh_authority(self):
        self.make(self.temp / "one", "--no-register")
        self.make(self.temp / "two", "--no-register")
        first = (self.temp / "one" / "root.crt").read_bytes()
        self.assertNotEqual(first, (self.temp / "two" / "root.crt").read_bytes())
        self.assertIsNone(authorities.find("local-test"))

    def test_an_existing_authority_needs_force(self):
        self.make()
        old = authorities.find("local-test").roots[0].sha256
        before = (self.home / "test-authority" / "root.crt").read_bytes()
        code, _, err = run_cli("test-authority", "init")
        self.assertEqual(code, 2)
        self.assertIn("--force", err)
        self.assertEqual((self.home / "test-authority" / "root.crt").read_bytes(), before)
        out = self.make("--force")
        self.assertIn("Replaced", out)
        new = authorities.find("local-test").roots[0].sha256
        self.assertNotEqual(old, new)
        self.assertFalse((self.home / "authorities" / f"{old}.pem").exists())

    def test_a_listed_local_test_needs_force_even_from_another_folder(self):
        self.make()
        code, _, err = run_cli("test-authority", "init", self.temp / "elsewhere")
        self.assertEqual(code, 2)
        self.assertIn("already has the test authority local-test", err)
        self.assertFalse((self.temp / "elsewhere").exists(), "nothing was written")
        self.make(self.temp / "elsewhere", "--no-register")

    def test_a_real_entry_named_local_test_is_never_replaced(self):
        run_cli("authority", "add", "local-test", "http://tsa.example.test/")
        code, _, err = run_cli("test-authority", "init", "--force")
        self.assertEqual(code, 2)
        self.assertIn("not a test authority", err)
        self.assertFalse((self.home / "test-authority").exists())

    def test_bad_arguments(self):
        file_in_the_way = self.write("a-file", b"x")
        for extra in (("--days", "0"), ("--days", "36501"), ("--days", "many"), ("--name", "two\nlines"), ("--name", "x" * 41), (file_in_the_way,)):
            with self.subTest(extra):
                code, _, err = run_cli("test-authority", "init", *extra)
                self.assertEqual(code, 2, err)
                self.assertNotIn("Traceback", err)
        self.assertIsNone(authorities.find("local-test"))

    def test_days_sets_the_validity(self):
        self.make("--days", "1", "--name", "Example Org")
        root = load_certificates(self.home / "test-authority" / "root.crt")[0]
        self.assertLess(root.not_after - root.not_before, timedelta(days=1, hours=2))
        self.assertIn("TEST ONLY Example Org root", root.subject.display())

    def test_info(self):
        self.make()
        code, out, _ = run_cli("test-authority", "info")
        self.assertEqual(code, 0)
        root = load_certificates(self.home / "test-authority" / "root.crt")[0]
        for phrase in (root.sha256, "http://127.0.0.1:3161/tsr", "Policy: 2.25.", "Listed as local-test", "prove nothing"):
            self.assertIn(phrase, out)
        run_cli("authority", "remove", "local-test")
        self.assertIn("Not in the authority list", run_cli("test-authority", "info")[1])

    def test_info_and_serve_on_a_missing_or_damaged_folder(self):
        for command in ("info", "serve"):
            code, _, err = run_cli("test-authority", command, self.temp / "nothing")
            self.assertEqual(code, 2)
            self.assertIn("test-authority init", err)
        self.make(self.temp / "ta", "--no-register")
        for name, data in (("authority.json", b"{"), ("authority.json", b'{"format": 1, "name": "x", "policy": "1.2", "created": ""}'), ("signer.crt", b"junk"), ("TEST-ONLY-signer-key.pem", b"junk")):
            with self.subTest(name):
                self.make(self.temp / "ta", "--no-register", "--force")
                (self.temp / "ta" / name).write_bytes(data)
                code, _, err = run_cli("test-authority", "info", self.temp / "ta")
                self.assertEqual(code, 2, err)
                self.assertNotIn("Traceback", err)

    def test_parts_from_two_authorities_do_not_load(self):
        self.make(self.temp / "a", "--no-register")
        self.make(self.temp / "b", "--no-register")
        (self.temp / "a" / "TEST-ONLY-signer-key.pem").write_bytes((self.temp / "b" / "TEST-ONLY-signer-key.pem").read_bytes())
        code, _, err = run_cli("test-authority", "info", self.temp / "a")
        self.assertEqual(code, 2)
        self.assertIn("do not belong together", err)

    def test_a_newer_folder_is_refused(self):
        self.make(self.temp / "ta", "--no-register")
        config = self.temp / "ta" / "authority.json"
        config.write_text(json.dumps(dict(json.loads(config.read_text()), format=2)))
        self.assertIn("newer version", run_cli("test-authority", "info", self.temp / "ta")[2])


class Answers(TestAuthorityCase):
    """The authority's answers, without the network."""

    def setUp(self):
        super().setUp()
        self.make()
        self.authority = local_authority.load()

    def answer(self, body, moment=None):
        return tsp.parse_response(self.authority.answer(body, moment))

    def assert_refused(self, body, failure):
        response = self.answer(body)
        self.assertEqual(response.status, 2)
        self.assertEqual(response.failure_bits, [failure])
        self.assertIsNone(response.tst_info)

    def test_a_good_request_is_granted_with_nonce_and_certificates(self):
        response = self.answer(request(cert_req=True))
        self.assertEqual(response.status, 0)
        self.assertEqual(response.tst_info.nonce, 12345)
        self.assertEqual(response.tst_info.policy, self.authority.policy)
        self.assertEqual(len(response.signed_data.certificates), 2)
        self.assertEqual(len(self.answer(request(cert_req=False)).signed_data.certificates), 0)
        self.assertIsNone(self.answer(request(nonce=None)).tst_info.nonce)

    def test_every_strong_hash_is_honored(self):
        for algorithm in (hashes.SHA256, hashes.by_name("sha384"), hashes.by_name("sha512")):
            with self.subTest(algorithm.name):
                response = self.answer(request(algorithm=algorithm))
                self.assertEqual(response.tst_info.hash_oid, algorithm.oid)
                self.assertEqual(response.tst_info.digest, algorithm.digest(DATA))

    def test_requests_are_refused_the_way_rfc_3161_says(self):
        self.assert_refused(b"not a request", local_authority.BAD_DATA_FORMAT)
        self.assert_refused(b"\x30\x80" * 5000, local_authority.BAD_DATA_FORMAT)
        self.assert_refused(b"", local_authority.BAD_DATA_FORMAT)
        self.assert_refused(request(algorithm=hashes.by_name("sha1")), local_authority.BAD_ALG)
        self.assert_refused(request(algorithm=hashes.by_name("md5")), local_authority.BAD_ALG)
        self.assert_refused(request(digest=b"short"), local_authority.BAD_DATA_FORMAT)
        self.assert_refused(request(policy="1.2.3.4"), local_authority.UNACCEPTED_POLICY)
        own = self.answer(request(policy=self.authority.policy))
        self.assertEqual(own.status, 0)
        good = request()
        version_two = good.replace(b"\x02\x01\x01", b"\x02\x01\x02", 1)
        self.assert_refused(version_two, local_authority.BAD_REQUEST)
        with_extensions = good[:1] + bytes([good[1] + 4]) + good[2:] + b"\xa0\x02\x30\x00"
        self.assert_refused(with_extensions, local_authority.UNACCEPTED_EXTENSION)

    def test_a_fixed_time_is_signed(self):
        moment = datetime(2030, 5, 6, 7, 8, 9, 123456, tzinfo=timezone.utc)
        self.assertEqual(self.answer(request(), moment).tst_info.gen_time, moment.replace(microsecond=0))


class Server(TestAuthorityCase):
    def setUp(self):
        super().setUp()
        self.make()

    def post(self, server, body, kind="application/timestamp-query", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        self.addCleanup(connection.close)
        connection.request("POST", "/tsr", body=body, headers=headers or {"Content-Type": kind})
        answer = connection.getresponse()
        return answer.status, answer.read(), answer

    def raw(self, server, data):
        with socket.create_connection(("127.0.0.1", server.port), timeout=10) as connection:
            connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)

    def test_get_pages(self):
        server = self.serve()
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
        connection.request("GET", "/")
        answer = connection.getresponse()
        self.assertEqual(answer.status, 200)
        self.assertIn(b"TEST ONLY", answer.read())
        self.assertTrue(answer.getheader("Content-Type").startswith("text/plain"))
        connection.close()
        for method, path, status in (("GET", "/elsewhere", 404), ("PUT", "/tsr", 501), ("DELETE", "/", 501)):
            with self.subTest(method):
                connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
                connection.request(method, path)
                self.assertEqual(connection.getresponse().status, status)
                connection.close()

    def test_hostile_http_requests(self):
        server = self.serve()
        cases = (
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Type: application/timestamp-query\r\n\r\n", b" 411 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n", b" 400 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n", b" 400 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n", b" 400 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Length: 10000000\r\n\r\n", b" 413 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", b" 411 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi", b" 415 "),
            (b"POST /tsr HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\nshort", b""),
            (b"GARBAGE\r\n\r\n", b" 400 "),
            (b"POST /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", b" 414 "),
        )
        for data, expected in cases:
            with self.subTest(data[:60]):
                answer = self.raw(server, data)
                self.assertIn(expected.strip(), answer[:200])
        status, body, _ = self.post(server, request())
        self.assertEqual(status, 200, "still answering after all that")
        self.assertEqual(tsp.parse_response(body).status, 0)

    def test_oversized_bodies_are_refused_before_reading(self):
        server = self.serve()
        status, body, _ = self.post(server, b"\x30" * (local_server.MAX_REQUEST_BYTES + 1))
        self.assertEqual(status, 413)
        status, body, answer = self.post(server, b"\x00" * 10)
        self.assertEqual(status, 200)
        self.assertEqual(answer.getheader("Content-Type"), "application/timestamp-reply")
        self.assertEqual(tsp.parse_response(body).failure_bits, [local_authority.BAD_DATA_FORMAT])

    def test_content_type_parameters_are_accepted(self):
        server = self.serve()
        status, body, _ = self.post(server, request(), "Application/Timestamp-Query; charset=binary")
        self.assertEqual(status, 200)

    def test_loopback_only(self):
        authority = local_authority.load()
        for host in ("0.0.0.0", "::", "192.0.2.1", "10.0.0.1", "example.test", "", "127.0.0.1.example.test", "::ffff:192.0.2.1"):
            with self.subTest(host), self.assertRaises(UsageError) as caught:
                LocalServer(authority, host)
            self.assertIn("loopback", str(caught.exception))
        self.assertEqual(local_server.loopback_host("localhost"), "127.0.0.1")
        self.assertEqual(local_server.loopback_host("127.0.0.2"), "127.0.0.2")
        self.assertEqual(local_server.loopback_host("[::1]"), "::1")
        code, _, err = run_cli("test-authority", "serve", "--host", "0.0.0.0", "--port", "0")
        self.assertEqual(code, 2)
        self.assertIn("loopback", err)

    def test_ipv6_loopback_when_this_computer_has_it(self):
        try:
            server = LocalServer(local_authority.load(), "::1").start()
        except UsageError:
            self.skipTest("this computer has no IPv6 loopback")
        self.addCleanup(server.stop)
        self.assertTrue(server.url.startswith("http://[::1]:"))
        manifest = self.write("m.txt", DATA)
        code, _, err = run_cli("stamp", manifest, "--tsa-url", server.url, "--retries", "0")
        self.assertEqual(code, 0, err)

    def test_a_port_in_use_is_a_plain_error(self):
        first = self.serve()
        with self.assertRaises(UsageError) as caught:
            LocalServer(local_authority.load(), port=first.port).start()
        self.assertIn(f"port {first.port}", str(caught.exception))
        self.assertEqual(run_cli("test-authority", "serve", "--port", "70000")[0], 2)

    def test_the_server_counts_requests_and_stops(self):
        server = self.serve()
        self.post(server, request())
        self.post(server, request())
        self.assertEqual(server.requests, 2)
        port = server.port
        server.stop()
        server.stop()
        self.assertEqual(server.requests, 2)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()

    def test_context_manager(self):
        with LocalServer(local_authority.load()) as server:
            status, _, _ = self.post(server, request())
            self.assertEqual(status, 200)


class Switches(TestAuthorityCase):
    """What stamp does when the test authority misbehaves on purpose."""

    def setUp(self):
        super().setUp()
        self.make()
        self.manifest_path = self.write("m.txt", DATA)

    def stamp(self, server, *extra):
        return run_cli("stamp", self.manifest_path, "--tsa-url", server.url, *extra)

    def saved(self):
        return sorted(path.name for path in self.temp.iterdir() if path.is_file())

    def test_refuse(self):
        code, _, err = self.stamp(self.serve(refuse=True), "--retries", "0")
        self.assertEqual(code, 1)
        self.assertIn("rejected", err)
        self.assertIn("--refuse", err)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_busy_then_granted(self):
        server = self.serve(busy=1)
        code, _, err = self.stamp(server)
        self.assertEqual(code, 0, err)
        self.assertIn("limiting requests (HTTP 429)", err)
        self.assertIn("Asking again", err)
        self.assertEqual(server.requests, 2)

    def test_busy_beyond_the_retries(self):
        server = self.serve(busy=5)
        code, _, err = self.stamp(server, "--retries", "0")
        self.assertEqual(code, 1)
        self.assertIn("HTTP 429", err)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_delay_beyond_the_timeout(self):
        started = time.monotonic()
        code, _, err = self.stamp(self.serve(delay=5), "--retries", "0", "--timeout", "0.5")
        self.assertEqual(code, 1)
        self.assertIn("Nothing was saved", err)
        self.assertLess(time.monotonic() - started, 4)

    def test_delay_within_the_timeout(self):
        started = time.monotonic()
        code, _, err = self.stamp(self.serve(delay=0.3))
        self.assertEqual(code, 0, err)
        self.assertGreaterEqual(time.monotonic() - started, 0.3)

    def test_broken(self):
        code, _, err = self.stamp(self.serve(broken=True), "--retries", "0")
        self.assertEqual(code, 1)
        self.assertIn("not saved", err)
        self.assertEqual(self.saved(), ["m.txt"])

    def test_fixed_time_inside_the_validity(self):
        moment = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=30)
        code, out, err = self.stamp(self.serve(fixed_time=moment))
        self.assertEqual(code, 0, err)
        self.assertIn(f"Time in token: {moment:%Y-%m-%d %H:%M:%S} UTC", out)

    def test_fixed_time_before_the_certificates_is_not_saved(self):
        code, _, err = self.stamp(self.serve(fixed_time=datetime(2020, 1, 1, tzinfo=timezone.utc)), "--retries", "0")
        self.assertEqual(code, 1)
        self.assertIn("not yet valid at the token's time", err)

    def test_fixed_time_in_the_future_is_not_saved(self):
        code, _, err = self.stamp(self.serve(fixed_time=datetime.now(timezone.utc) + timedelta(days=30)), "--retries", "0")
        self.assertEqual(code, 1)
        self.assertIn("in the future", err)

    def test_policy_requested_by_stamp(self):
        server = self.serve()
        code, _, err = self.stamp(server, "--policy", "1.2.3.4", "--retries", "0")
        self.assertEqual(code, 1)
        self.assertIn("requested policy is not supported", err)
        policy = local_authority.load().policy
        self.assertEqual(self.stamp(server, "--policy", policy)[0], 0)

    def test_switches_on_the_command_line(self):
        for extra in (("--busy", "-1"), ("--busy", "1001"), ("--delay", "301"), ("--delay", "soon"), ("--time", "yesterday"), ("--port", "x")):
            with self.subTest(extra):
                self.assertEqual(run_cli("test-authority", "serve", "--port", "0", *extra)[0], 2)

    def test_serve_command_prints_its_url_and_stops_on_ctrl_c(self):
        with mock.patch.object(LocalServer, "serve_forever", side_effect=KeyboardInterrupt):
            code, out, _ = run_cli("test-authority", "serve", "--port", "0", "--busy", "2", "--refuse", "--time", "2026-03-01T12:00:00Z")
        self.assertEqual(code, 130)
        self.assertRegex(out, r"answering at http://127\.0\.0\.1:\d+/tsr")
        self.assertIn("prove nothing", out)
        self.assertIn("Misbehaving on purpose: --refuse, --busy 2, --time 2026-03-01T12:00:00Z", out)
        self.assertIn("--tsa-url", out, "the port differs from the listed one")
        self.assertIn("Stopped the test authority.", out)


class Offline(TestAuthorityCase):
    """Seal, stamp with --authority local-test, verify, report and show, all on this computer."""

    def test_end_to_end(self):
        self.make()
        manifest = self.manifest()
        server = LocalServer(local_authority.load(), port=0).start()
        self.addCleanup(server.stop)
        listed = authorities.find("local-test")
        with mock.patch.object(authorities, "find", return_value=authorities.Entry(**dict(listed.__dict__, url=server.url))):
            code, out, err = run_cli("stamp", manifest, "--authority", "local-test")
        self.assertEqual(code, 0, err)
        self.assertIn("From the authority list: local-test", out)
        self.assertIn("local test authority. This token proves nothing to anyone else", out)
        code, out, err = run_cli("verify", manifest)
        self.assertEqual(code, 0, out + err)
        self.assertIn("RESULT: VERIFIED", out)
        self.assertIn("trusted through the root of local-test in your authority list, a local test authority", out)
        self.assertIn("comes from local-test, a local test authority on this computer", out)
        code, out, _ = run_cli("verify", manifest, "--json")
        data = json.loads(out)
        self.assertEqual((data["overall"], data["test_authority"]), ("VERIFIED", "local-test"))
        code, out, _ = run_cli("report", manifest, "--out", "-")
        self.assertEqual(code, 0)
        self.assertIn("a local test authority on this computer. It proves nothing to anyone else", out)
        code, out, _ = run_cli("report", manifest, "--format", "html", "--out", "-")
        self.assertIn("a local test authority on this computer", out)
        token = manifest.with_suffix(".tsr")
        code, out, _ = run_cli("show", token)
        self.assertIn("comes from local-test, a local test authority", out)
        self.assertEqual(json.loads(run_cli("show", token, "--json")[1])["test_authority"], "local-test")
        code, out, _ = run_cli("verify", manifest, "--ca", self.home / "test-authority" / "root.crt")
        self.assertEqual(code, 0)
        self.assertIn("comes from local-test", out, "said with --ca too, while the list names it")

    def test_stamp_authority_errors(self):
        manifest = self.write("m.txt", DATA)
        for extra, phrase in (
            (("--authority", "nobody"), "no authority named"),
            (("--authority", "FreeTSA", "--tsa-url", "http://127.0.0.1:9/"), "cannot be used together"),
            (("--authority", "FreeTSA", "--ca", self.write("r.crt", b"x")), "--ca cannot be added"),
        ):
            with self.subTest(phrase):
                code, _, err = run_cli("stamp", manifest, *extra)
                self.assertEqual(code, 2)
                self.assertIn(phrase, err)
        run_cli("authority", "add", "bare", "http://127.0.0.1:9/tsr")
        code, _, err = run_cli("stamp", manifest, "--authority", "bare")
        self.assertEqual(code, 2)
        self.assertIn("Nothing was sent", err)

    def test_stamp_takes_url_hash_and_policy_from_the_entry_and_checks_its_roots(self):
        self.make()
        authority = local_authority.load()
        server = self.serve()
        root = self.home / "test-authority" / "root.crt"
        run_cli("authority", "add", "mine", server.url, "--root", root, "--hash", "sha512", "--policy", authority.policy)
        manifest = self.write("m.txt", DATA)
        code, out, err = run_cli("stamp", manifest, "--authority", "mine")
        self.assertEqual(code, 0, err)
        saved = tsp.parse_request(manifest.with_suffix(".tsq").read_bytes())
        self.assertEqual((saved.hash_oid, saved.policy), (hashes.by_name("sha512").oid, authority.policy))
        self.assertNotIn("This token proves nothing", out, "mine is not marked as a test authority")
        code, _, err = run_cli("stamp", manifest, "--authority", "mine", "--hash", "sha256", "--out", self.temp / "second.tsr")
        self.assertEqual(code, 0, err)
        self.assertEqual(tsp.parse_request((self.temp / "second.tsq").read_bytes()).hash_oid, hashes.SHA256.oid)
        other = self.temp / "other"
        self.make(other, "--no-register")
        run_cli("authority", "add", "wrong-root", server.url, "--root", other / "root.crt")
        code, _, err = run_cli("stamp", manifest, "--authority", "wrong-root", "--out", self.temp / "third.tsr")
        self.assertEqual(code, 1)
        self.assertIn("does not reach the roots listed for wrong-root", err)
        self.assertFalse((self.temp / "third.tsr").exists())

    def test_expired_since_is_noted_and_still_verifies(self):
        self.make("--days", "1")
        manifest = self.write("m.txt", DATA)
        server = self.serve()
        self.assertEqual(run_cli("stamp", manifest, "--tsa-url", server.url)[0], 0)
        later = datetime.now(timezone.utc) + timedelta(days=3)
        outcome = verification.verify(verification.VerifyOptions(manifest, skip_files=True, now=later))
        self.assertEqual(outcome.check("chain").status.value, "pass")
        self.assertTrue(any("has expired since" in note for note in outcome.notes))
        self.assertEqual(outcome.test_authority, "local-test")

    @requires_openssl
    def test_openssl_accepts_its_tokens(self):
        self.make()
        manifest = self.write("m.txt", DATA)
        server = self.serve()
        self.assertEqual(run_cli("stamp", manifest, "--tsa-url", server.url)[0], 0)
        root = load_certificates(self.home / "test-authority" / "root.crt")
        result = ts_verify(manifest, manifest.with_suffix(".tsr"), root, [], None, False)
        self.assertEqual(result.answer, YES, result.output)
        tampered = self.write("tampered.txt", DATA + b"x")
        self.assertNotEqual(ts_verify(tampered, manifest.with_suffix(".tsr"), root, [], None, False).answer, YES)

    @requires_openssl
    def test_openssl_reads_its_key_file(self):
        self.make()
        from evidence_seal import openssl_bridge

        program = openssl_bridge.find_openssl()
        key = self.home / "test-authority" / "TEST-ONLY-signer-key.pem"
        result = subprocess.run([program, "ec", "-in", str(key), "-pubout"], capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        signer = Certificate(load_certificates(self.home / "test-authority" / "signer.crt")[0].raw)
        self.assertIn(b"PUBLIC KEY", result.stdout)
        self.assertTrue(signer.subject.display().startswith("O=evidence-seal local test authority"))

    def test_the_real_serve_command_in_its_own_process(self):
        self.make()
        environment = dict(os.environ, PYTHONPATH=str(ROOT_OF_REPO))
        process = subprocess.Popen(
            [sys.executable, "-m", "evidence_seal", "test-authority", "serve", "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            cwd=str(self.temp),
        )
        self.addCleanup(process.wait, 10)
        self.addCleanup(process.kill)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stderr.close)
        line = process.stdout.readline().decode("utf-8")
        self.assertIn("answering at http://127.0.0.1:", line)
        url = line.strip().rsplit(" ", 1)[-1]
        manifest = self.write("m.txt", DATA)
        code, _, err = run_cli("stamp", manifest, "--tsa-url", url, "--retries", "0")
        self.assertEqual(code, 0, err)
        code, out, _ = run_cli("verify", manifest, "--skip-files")
        self.assertIn("comes from local-test", out)
