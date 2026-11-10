"""Helpers for the web interface tests: a server in this process, a client, and a multipart encoder."""

import http.client
import json
import os
import re
import time
import urllib.parse
from unittest import mock

from evidence_seal.web import security
from evidence_seal.web.server import WebServer
from tests.library_support import LibraryTestCase

BOUNDARY = "evidence-seal-test-boundary"
_TOKEN = re.compile(r'name="form_token" value="([^"]+)"')


class Answer:
    def __init__(self, response, body):
        self.status = response.status
        self.header_list = response.getheaders()
        self.headers = {name.lower(): value for name, value in self.header_list}
        self.body = body

    @property
    def text(self):
        return self.body.decode("utf-8")

    def json(self):
        return json.loads(self.body.decode("ascii"))

    def __repr__(self):
        return f"<Answer {self.status} {self.body[:400]!r}>"


def multipart(fields, files=(), boundary=BOUNDARY):
    """A multipart/form-data body. fields: (name, text) pairs; files: (name, filename, bytes) triples."""
    chunks = []
    for name, value in fields:
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode() + value.encode() + b"\r\n")
    for name, filename, data in files:
        head = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        )
        chunks.append(head.encode() + data + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


class WebTestCase(LibraryTestCase):
    """A web server on a free loopback port for each test, stopped and forgotten afterwards."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.server = WebServer().start()
        self.addCleanup(self.server.stop)
        self.host = f"127.0.0.1:{self.server.port}"
        self.cookie = None

    @property
    def session(self):
        return self.server.app.sessions.find([self.cookie]) if self.cookie else None

    @property
    def form_token(self):
        return self.session.form_token

    def raw(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=20)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            sent = {"Host": self.host}
            if self.cookie:
                sent["Cookie"] = f"{security.cookie_name(self.server.port)}={self.cookie}"
            if body is not None:
                sent["Content-Length"] = str(len(body))
            sent.update(headers or {})
            for name, value in sent.items():
                if value is not None:
                    connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return Answer(response, response.read())
        finally:
            connection.close()

    def login(self):
        answer = self.raw("GET", f"/?key={urllib.parse.quote(self.server.key)}")
        self.assertEqual(answer.status, 303, answer)
        cookie = answer.headers["set-cookie"]
        self.cookie = cookie.split(";", 1)[0].split("=", 1)[1]
        return answer

    def get(self, path, status=200, **headers):
        answer = self.raw("GET", path, headers=headers)
        self.assertEqual(answer.status, status, answer)
        return answer

    def post(self, path, fields=(), status=None, token=True, **headers):
        pairs = list(fields.items()) if isinstance(fields, dict) else list(fields)
        if token:
            pairs.append(("form_token", self.form_token))
        body = urllib.parse.urlencode(pairs).encode()
        sent = {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://{self.host}"}
        sent.update(headers)
        answer = self.raw("POST", path, body, sent)
        if status is not None:
            self.assertEqual(answer.status, status, answer)
        return answer

    def api(self, method, path, data=None, status=None, **headers):
        """Calls the JSON API with the access key, as a program would."""
        sent = {"Authorization": f"Bearer {self.server.key}", "Accept": "application/json"}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            sent["Content-Type"] = "application/json"
        elif method == "POST":
            body = b""
        sent.update(headers)
        saved, self.cookie = self.cookie, None
        try:
            answer = self.raw(method, "/api/v1" + path, body, sent)
        finally:
            self.cookie = saved
        if status is not None:
            self.assertEqual(answer.status, status, answer)
        return answer

    def tokens_in(self, html):
        return _TOKEN.findall(html)

    def wait_for(self, job_id, seconds=30):
        """Polls a job until it finishes, as the page's script does."""
        deadline = time.monotonic() + seconds
        while True:
            job = self.api("GET", f"/jobs/{job_id}", status=200).json()["job"]
            if job["state"] not in ("waiting", "running"):
                return job
            if time.monotonic() > deadline:
                self.fail(f"job {job_id} did not finish: {job}")
            time.sleep(0.02)

    def job_of(self, answer):
        """The job a 303 to its page names."""
        location = answer.headers.get("location", "")
        found = re.fullmatch(r"/jobs/([0-9a-f]{32})", location)
        self.assertIsNotNone(found, answer)
        return found.group(1)
