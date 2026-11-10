"""The web interface's security model: the key, sessions, Host, Origin, form tokens, headers and limits."""

import os
import socket
import unittest
from pathlib import Path
from unittest import mock

from evidence_seal import home
from evidence_seal.errors import UsageError
from evidence_seal.web import inputs, security
from evidence_seal.web.routing import HttpError
from evidence_seal.web.server import MAX_HEADERS, WebServer
from tests.support import HomeTestCase
from tests.web_support import WebTestCase

PAGE_HEADERS = ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy")


class Key(WebTestCase):
    def test_nothing_answers_without_the_key(self):
        for path in ("/", "/settings", "/assets/style.css", "/seals/" + "0" * 64):
            with self.subTest(path):
                answer = self.raw("GET", path)
                self.assertEqual(answer.status, 401, answer)
                self.assertIn("address that serve printed", answer.text)
        answer = self.raw("GET", "/api/v1/health")
        self.assertEqual(answer.status, 401)
        self.assertEqual(answer.json()["error"]["code"], "no_key")

    def test_a_wrong_key_is_refused(self):
        self.assertEqual(self.raw("GET", "/?key=wrong").status, 401)
        self.assertEqual(self.raw("GET", "/?key=").status, 401)
        answer = self.raw("GET", "/api/v1/health", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(answer.status, 401)
        self.assertEqual(answer.json()["error"]["code"], "wrong_key")
        self.assertEqual(len(self.server.app.sessions), 0)

    def test_the_key_becomes_a_strict_http_only_cookie_and_leaves_the_address(self):
        answer = self.raw("GET", f"/settings?key={self.server.key}&page=2")
        self.assertEqual(answer.status, 303)
        self.assertEqual(answer.headers["location"], "/settings?page=2")
        cookie = answer.headers["set-cookie"]
        self.assertTrue(cookie.startswith(f"evidence_seal_{self.server.port}="))
        for part in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(part, cookie)
        self.assertNotIn(self.server.key, cookie)
        self.cookie = cookie.split(";")[0].split("=", 1)[1]
        self.assertEqual(self.raw("GET", "/settings").status, 200)

    def test_a_cookie_for_another_port_or_a_made_up_one_does_not_count(self):
        self.login()
        good = self.cookie
        self.cookie = None
        answer = self.raw("GET", "/", headers={"Cookie": f"evidence_seal_1={good}"})
        self.assertEqual(answer.status, 401)
        answer = self.raw("GET", "/", headers={"Cookie": f"evidence_seal_{self.server.port}=made-up"})
        self.assertEqual(answer.status, 401)
        stale = f"evidence_seal_{self.server.port}=old; evidence_seal_{self.server.port}={good}"
        self.assertEqual(self.raw("GET", "/", headers={"Cookie": stale}).status, 200)

    def test_the_api_takes_the_key_as_a_bearer_token(self):
        answer = self.api("GET", "/health", status=200)
        self.assertEqual(answer.json()["status"], "ok")
        self.assertEqual(answer.json()["api_version"], 1)

    def test_the_api_does_not_trade_a_key_in_the_address_for_a_cookie(self):
        answer = self.raw("GET", f"/api/v1/health?key={self.server.key}")
        self.assertEqual(answer.status, 401)
        self.assertNotIn("set-cookie", answer.headers)

    def test_sessions_are_bounded(self):
        sessions = security.Sessions(limit=3)
        first = sessions.create()
        for _ in range(3):
            sessions.create()
        self.assertEqual(len(sessions), 3)
        self.assertIsNone(sessions.find([first.id]))

    def test_each_run_has_a_new_key(self):
        other = WebServer()
        self.assertNotEqual(other.key, self.server.key)
        self.assertGreaterEqual(len(self.server.key), 40)


class Host(WebTestCase):
    def test_a_host_header_for_another_name_is_refused_even_with_the_key(self):
        for host in ("evil.example.test", f"evil.example.test:{self.server.port}", "127.0.0.1:1", "127.0.0.1", f"127.0.0.2:{self.server.port}"):
            with self.subTest(host):
                answer = self.raw("GET", "/api/v1/health", headers={"Host": host, "Authorization": f"Bearer {self.server.key}"})
                self.assertEqual(answer.status, 400, answer)
                self.assertEqual(answer.json()["error"]["code"], "wrong_host")
                answer = self.raw("GET", f"/?key={self.server.key}", headers={"Host": host})
                self.assertEqual(answer.status, 400)
                self.assertNotIn("set-cookie", answer.headers)

    def test_a_missing_host_header_is_refused(self):
        answer = self.raw("GET", "/api/v1/health", headers={"Host": None, "Authorization": f"Bearer {self.server.key}"})
        self.assertEqual(answer.status, 400)

    def test_localhost_names_the_same_server(self):
        answer = self.raw("GET", "/api/v1/health", headers={"Host": f"localhost:{self.server.port}", "Authorization": f"Bearer {self.server.key}"})
        self.assertEqual(answer.status, 200)


class Changes(WebTestCase):
    def setUp(self):
        super().setUp()
        self.login()
        _, self.manifest_path = self.sealed_and_stamped()
        self.sha = self.only_seal()["manifest_sha256"]

    def tags(self):
        with self.open() as opened:
            return opened.seal(self.sha)["tags"]

    def test_a_change_needs_the_form_token(self):
        answer = self.post(f"/seals/{self.sha}/tags", {"tag": "a"}, token=False)
        self.assertEqual(answer.status, 403)
        self.assertIn("form token", answer.text)
        answer = self.post(f"/seals/{self.sha}/tags", {"tag": "a", "form_token": "wrong"}, token=False)
        self.assertEqual(answer.status, 403)
        self.assertEqual(self.tags(), [])

    def test_the_form_token_header_works_too(self):
        self.post(f"/seals/{self.sha}/tags", {"tag": "a"}, status=303, token=False, **{"X-Form-Token": self.form_token})
        self.assertEqual(self.tags(), ["a"])

    def test_pages_carry_the_form_token(self):
        text = self.get(f"/seals/{self.sha}").text
        self.assertEqual(set(self.tokens_in(text)), {self.form_token})

    def test_a_post_from_another_origin_is_refused(self):
        for origin in ("http://evil.example.test", "http://127.0.0.1:1", "null", f"https://127.0.0.1:{self.server.port}"):
            with self.subTest(origin):
                answer = self.post(f"/seals/{self.sha}/tags", {"tag": "a"}, Origin=origin)
                self.assertEqual(answer.status, 403, answer)
                self.assertIn("another web page", answer.text)
        for site in ("cross-site", "same-site"):
            with self.subTest(site):
                answer = self.post(f"/seals/{self.sha}/tags", {"tag": "a"}, Origin=None, **{"Sec-Fetch-Site": site})
                self.assertEqual(answer.status, 403)
        self.assertEqual(self.tags(), [])

    def test_a_bearer_post_from_another_origin_is_refused_too(self):
        answer = self.api("POST", f"/seals/{self.sha}/tags", {"tag": "a"}, Origin="http://evil.example.test")
        self.assertEqual(answer.status, 403)
        self.assertEqual(answer.json()["error"]["code"], "cross_origin")

    def test_same_origin_without_an_origin_header_is_accepted(self):
        self.post(f"/seals/{self.sha}/tags", {"tag": "a"}, status=303, Origin=None, **{"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(self.tags(), ["a"])

    def test_changes_are_never_made_by_get(self):
        self.get(f"/seals/{self.sha}/tags?tag=a", status=405)
        answer = self.get(f"/seals/{self.sha}/forget?confirm=yes")
        self.assertIn("confirm", answer.text)
        with self.open() as opened:
            self.assertIsNotNone(opened.seal(self.sha))

    def test_a_get_with_a_body_is_refused(self):
        answer = self.raw("GET", "/", b"x=1", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(answer.status, 400)

    def test_an_unknown_body_type_is_refused(self):
        answer = self.raw("POST", f"/seals/{self.sha}/tags", b"<x/>", {"Content-Type": "text/xml", "Origin": f"http://{self.host}"})
        self.assertEqual(answer.status, 415)


class Headers(WebTestCase):
    def test_every_answer_carries_the_security_headers(self):
        answers = [self.raw("GET", "/"), self.raw("GET", "/api/v1/health")]
        self.login()
        answers += [self.get("/"), self.get("/assets/app.js"), self.raw("GET", "/missing"), self.raw("PUT", "/", b"")]
        answers.append(self.api("GET", "/seals/" + "0" * 64))
        for answer in answers:
            with self.subTest(answer.status):
                for name in PAGE_HEADERS:
                    self.assertIn(name, answer.headers)
                self.assertEqual(answer.headers["x-content-type-options"], "nosniff")
                self.assertEqual(answer.headers["x-frame-options"], "DENY")
                self.assertEqual(answer.headers["referrer-policy"], "no-referrer")
                self.assertIn("frame-ancestors 'none'", answer.headers["content-security-policy"])
                self.assertNotIn("Python", answer.headers.get("server", ""))

    def test_pages_allow_no_inline_script_or_style(self):
        self.login()
        policy = self.get("/").headers["content-security-policy"]
        self.assertIn("script-src 'self'", policy)
        self.assertIn("style-src 'self'", policy)
        self.assertNotIn("unsafe", policy)

    def test_an_unknown_method_gets_a_plain_answer(self):
        self.login()
        answer = self.raw("DELETE", "/api/v1/health")
        self.assertEqual(answer.status, 501)
        self.assertEqual(answer.json()["error"]["code"], "method_not_allowed")
        self.assertEqual(self.raw("GET", "/new/seal").status, 405)


class Limits(WebTestCase):
    def setUp(self):
        super().setUp()
        self.login()

    def send(self, data, read_first=False):
        """Sends raw bytes and returns the status line, for requests http.client will not make."""
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=20) as connection:
            connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)
            answer = b""
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                answer += chunk
        return answer.split(b"\r\n", 1)[0], answer

    def cookie_line(self):
        return f"Cookie: evidence_seal_{self.server.port}={self.cookie}\r\nHost: {self.host}\r\nOrigin: http://{self.host}\r\n"

    def test_an_oversized_body_is_refused_before_it_is_read(self):
        head = (
            f"POST /new/preview HTTP/1.1\r\n{self.cookie_line()}Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {10 ** 9}\r\n\r\n"
        )
        status, answer = self.send(head.encode())
        self.assertIn(b"413", status)
        upload = f"POST /check HTTP/1.1\r\n{self.cookie_line()}Content-Length: {10 ** 10}\r\n\r\n"
        self.assertIn(b"413", self.send(upload.encode())[0])

    def test_a_body_without_a_length_or_in_chunks_is_refused(self):
        head = f"POST /new/preview HTTP/1.1\r\n{self.cookie_line()}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        self.assertIn(b"411", self.send(head.encode())[0])
        head = f"POST /new/preview HTTP/1.1\r\n{self.cookie_line()}\r\n"
        self.assertIn(b"411", self.send(head.encode())[0])
        head = f"POST /new/preview HTTP/1.1\r\n{self.cookie_line()}Content-Length: -5\r\n\r\n"
        self.assertIn(b"400", self.send(head.encode())[0])

    def test_a_body_shorter_than_its_length_is_refused(self):
        head = f"POST /new/preview HTTP/1.1\r\n{self.cookie_line()}Content-Length: 100\r\n\r\nfolder=x"
        self.assertIn(b"400", self.send(head.encode())[0])

    def test_too_many_headers_are_refused(self):
        extra = "".join(f"X-Extra-{number}: {number}\r\n" for number in range(MAX_HEADERS))
        status, _ = self.send(f"GET / HTTP/1.1\r\n{self.cookie_line()}{extra}\r\n".encode())
        self.assertIn(b"431", status)

    def test_a_long_address_is_refused(self):
        status, _ = self.send(f"GET /?q={'a' * 9000} HTTP/1.1\r\n{self.cookie_line()}\r\n".encode())
        self.assertIn(b"414", status)
        status, _ = self.send(f"GET /{'a' * 70000} HTTP/1.1\r\n{self.cookie_line()}\r\n".encode())
        self.assertIn(b"414", status)

    def test_garbage_gets_a_plain_answer(self):
        status, answer = self.send(b"\x00\xff garbage\r\n\r\n")
        self.assertIn(b"400", status)
        self.assertIn(b"nosniff", answer)
        self.assertNotIn(b"Traceback", answer)

    def test_an_absolute_address_is_refused(self):
        status, _ = self.send(f"GET http://evil.example.test/ HTTP/1.1\r\n{self.cookie_line()}\r\n".encode())
        self.assertIn(b"400", status)
        # Newer releases of http.server fold the leading slashes into one, which then names no page here.
        status, _ = self.send(f"GET //evil.example.test/ HTTP/1.1\r\n{self.cookie_line()}\r\n".encode())
        self.assertRegex(status, rb" (400|404) ")

    def test_too_many_fields_and_duplicate_fields_are_refused(self):
        sha = "0" * 64
        many = [(f"f{number}", "x") for number in range(80)]
        self.assertEqual(self.post("/new/preview", many).status, 400)
        self.assertEqual(self.post("/new/preview", [("folder", "a"), ("folder", "b")]).status, 400)
        self.assertEqual(self.get(f"/?q=a&q=b", status=400).status, 400)
        self.assertEqual(self.post(f"/seals/{sha}/tags", {"tag": "x" * 20000}).status, 400)

    def test_a_bad_page_number_is_refused(self):
        for page in ("0", "-1", "abc", "9" * 20, "%D9%A1", "%FF"):
            with self.subTest(page):
                self.get(f"/?page={page}", status=400)


class TypedPaths(HomeTestCase):
    """Paths typed into forms are checked before anything opens them."""

    def refused(self, text):
        with self.assertRaises(HttpError) as caught:
            inputs.typed_path(text, "folder")
        self.assertEqual(caught.exception.status, 400)
        return caught.exception.message

    def test_hostile_paths_are_refused(self):
        hostile = [
            "", "   ", "relative/folder", "folder", ".", "..", "\\\\server\\share\\x", "//server/share/x",
            "\\\\.\\PhysicalDrive0", "\\\\?\\C:\\x", "a\x00b", "a\nb", "a\u202eb", "/a/../b", "C:\\a\\..\\b",
            "x" * 5000,
        ]
        if os.name == "nt":
            hostile += ["C:relative", "\\no-drive", "/no-drive", "C:\\a\\file.txt:stream", "C:\\a\\b:$DATA"]
        for text in hostile:
            with self.subTest(repr(text[:40])):
                self.refused(text)

    def test_the_home_folder_is_refused(self):
        home_folder = home.ensure_home()
        message = self.refused(str(home_folder / "library"))
        self.assertIn("own folder", message)
        self.refused(str(home_folder))

    def test_a_full_local_path_is_accepted(self):
        folder = self.temp / "work"
        folder.mkdir()
        self.assertEqual(inputs.existing_folder(f'"{folder}"'), Path(os.path.realpath(str(folder))))
        with self.assertRaises(HttpError):
            inputs.existing_folder(str(self.temp / "missing"))
        with self.assertRaises(HttpError):
            inputs.new_file(str(folder), "manifest file")
        with self.assertRaises(HttpError):
            inputs.new_file(str(self.temp / "missing" / "m.txt"), "manifest file")

    @unittest.skipUnless(os.name == "nt", "device names are a Windows matter")
    def test_a_device_name_is_refused(self):
        self.refused(str(self.temp / "CON"))


class Loopback(unittest.TestCase):
    def test_only_loopback_addresses_are_served(self):
        for host in ("0.0.0.0", "192.0.2.1", "example.test", "::", ""):
            with self.subTest(host):
                with self.assertRaises(UsageError) as caught:
                    WebServer(host)
                self.assertIn("web interface", str(caught.exception))

    def test_a_port_in_use_is_a_plain_error(self):
        with WebServer() as first:
            with self.assertRaises(UsageError) as caught:
                WebServer(port=first.port).bind()
            self.assertIn("another port", str(caught.exception))

    def test_ipv6_loopback(self):
        try:
            server = WebServer("::1").start()
        except UsageError:
            self.skipTest("IPv6 loopback is not available here")
        self.addCleanup(server.stop)
        self.assertTrue(server.url.startswith("http://[::1]:"))
        self.assertIn(f"[::1]:{server.port}", server.app.allowed)


class Command(HomeTestCase):
    def test_serve_prints_the_address_with_its_key_and_stops_on_ctrl_c(self):
        from tests.support import run_cli

        def interrupted(self):
            self.stop()
            raise KeyboardInterrupt

        with mock.patch.object(WebServer, "serve_forever", interrupted):
            code, out, err = run_cli("serve", "--port", "0")
        self.assertEqual(code, 130, err)
        self.assertIn("http://127.0.0.1:", out)
        self.assertIn("?key=", out)
        self.assertIn("Do not share it", out)
        self.assertIn("Stopped the web interface", out)

    def test_serve_refuses_bad_arguments(self):
        from tests.support import run_cli

        self.assertEqual(run_cli("serve", "--host", "0.0.0.0")[0], 2)
        self.assertEqual(run_cli("serve", "--port", "70000")[0], 2)
        self.assertEqual(run_cli("serve", "--profile", "no-such-profile")[0], 2)

    def test_open_uses_the_browser(self):
        from tests.support import run_cli

        opened = []
        with mock.patch.object(WebServer, "serve_forever", lambda self: self.stop()), mock.patch("webbrowser.open", lambda url: opened.append(url) or True):
            code, out, _ = run_cli("serve", "--open")
        self.assertEqual(code, 0)
        self.assertEqual(len(opened), 1)
        self.assertIn("?key=", opened[0])


if __name__ == "__main__":
    unittest.main()
