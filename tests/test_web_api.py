"""The JSON API under /api/v1/, the check of uploaded files, and a whole offline flow from the web."""

import json
import unittest

from evidence_seal import authorities, exporting, home, local_authority, report_formats
from evidence_seal.local_server import LocalServer
from tests.web_support import WebTestCase, multipart


class Api(WebTestCase):
    def setUp(self):
        super().setUp()
        self.folder, self.manifest_path = self.sealed_and_stamped()
        self.sha = self.only_seal()["manifest_sha256"]

    def test_errors_have_one_shape(self):
        for method, path, status, code in (
            ("GET", "/seals/" + "0" * 64, 404, "not_found"),
            ("GET", "/nothing", 404, "not_found"),
            ("GET", "/seal", 405, "method_not_allowed"),
            ("GET", "/seals?page=0", 400, "bad_request"),
            ("GET", f"/seals/{self.sha}/report/text", 409, "not_verified_yet"),
        ):
            with self.subTest(path):
                answer = self.api(method, path, status=status)
                self.assertEqual(answer.headers["content-type"], "application/json")
                self.assertEqual(set(answer.json()), {"error"})
                self.assertEqual(answer.json()["error"]["code"], code)
                self.assertTrue(answer.json()["error"]["message"])

    def test_seals_and_seal_detail(self):
        listing = self.api("GET", "/seals", status=200).json()
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["seals"][0]["manifest_sha256"], self.sha)
        self.assertEqual(self.api("GET", "/seals?q=nothing-like-it", status=200).json()["total"], 0)
        detail = self.api("GET", f"/seals/{self.sha}", status=200).json()
        self.assertEqual(detail["seal"]["purpose"], "purpose of work")
        self.assertEqual(len(detail["tokens"]), 1)
        self.assertEqual(detail["files"]["count"], 2)
        files = self.api("GET", f"/seals/{self.sha}/files", status=200).json()
        self.assertEqual([item["path"] for item in files["files"]], ["a.txt", "sub/b.bin"])

    def test_tags_and_forget(self):
        self.assertEqual(self.api("POST", f"/seals/{self.sha}/tags", {"tag": "court"}, status=200).json()["added"], True)
        self.assertEqual(self.api("GET", "/seals?tag=court", status=200).json()["total"], 1)
        self.assertEqual(self.api("POST", f"/seals/{self.sha}/untag", {"tag": "court"}, status=200).json()["removed"], True)
        self.api("POST", f"/seals/{self.sha}/tags", {}, status=400)
        self.api("POST", f"/seals/{self.sha}/forget", {}, status=400)
        self.api("POST", f"/seals/{self.sha}/forget", {"confirm": True}, status=200)
        self.api("GET", f"/seals/{self.sha}", status=404)

    def test_verify_job_then_reports(self):
        answer = self.api("POST", f"/seals/{self.sha}/verify", status=202)
        job_id = answer.json()["job"]["id"]
        self.assertEqual(answer.headers["location"], f"/api/v1/jobs/{job_id}")
        job = self.wait_for(job_id)
        self.assertEqual(job["state"], "done", job)
        verification = job["result"]["verification"]
        self.assertIn(verification["overall"], ("VERIFIED", "INCOMPLETE", "FAILED"))
        self.assertIn("token_checks", verification)
        self.assertIn(job_id, [item["id"] for item in self.api("GET", "/jobs", status=200).json()["jobs"]])
        for item in report_formats.REPORT_FORMATS:
            with self.subTest(item.name):
                report = self.api("GET", f"/jobs/{job_id}/report/{item.name}", status=200)
                self.assertEqual(report.headers["content-type"], item.media_type)
                self.api("GET", f"/seals/{self.sha}/report/{item.name}", status=200)
        self.api("GET", f"/jobs/{job_id}/report/nope", status=404)
        self.api("GET", f"/jobs/{'0' * 32}", status=404)

    def test_verify_with_a_hostile_folder_is_refused(self):
        for folder in ("\\\\server\\share", "relative", "/a/../b"):
            with self.subTest(folder):
                answer = self.api("POST", f"/seals/{self.sha}/verify", {"folder": folder}, status=400)
                self.assertEqual(answer.json()["error"]["code"], "bad_request")

    def test_the_verification_is_to_dict_unchanged(self):
        job = self.wait_for(self.api("POST", f"/seals/{self.sha}/verify", status=202).json()["job"]["id"])
        report = json.loads(self.api("GET", f"/jobs/{job['id']}/report/json", status=200).body)
        self.assertEqual(job["result"]["verification"]["overall"], report["verification"]["overall"])
        self.assertEqual(job["result"]["verification"], report["verification"])

    def test_exports(self):
        for name in exporting.EXPORT_FORMATS:
            with self.subTest(name):
                answer = self.api("GET", f"/seals/{self.sha}/export/{name}", status=200)
                self.assertIn(b"a.txt", answer.body)

    def test_new_seal_dry_run_then_job(self):
        folder = self.make_folder("fresh")
        preview = self.api("POST", "/seal", {"folder": str(folder), "purpose": "Example Org", "dry_run": True}, status=200).json()["preview"]
        self.assertEqual(preview["file_count"], 2)
        self.assertTrue(preview["ready"])
        self.assertEqual([path.name for path in self.temp.glob("fresh-manifest*")], [])
        answer = self.api("POST", "/seal", {"folder": str(folder), "purpose": "Example Org", "exclude": ["*.bin"]}, status=202)
        job = self.wait_for(answer.json()["job"]["id"])
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(job["result"]["file_count"], 1)
        self.assertTrue(job["result"]["recorded"])
        self.assertEqual(self.api("GET", "/seals", status=200).json()["total"], 2)
        no_purpose = self.api("POST", "/seal", {"folder": str(folder)}, status=400).json()
        self.assertIn("purpose", no_purpose["error"]["message"])

    def test_compare(self):
        (self.folder / "a.txt").write_bytes(b"other\n")
        self.seal(self.folder, "second.txt")
        other = [row["manifest_sha256"] for row in self.api("GET", "/seals", status=200).json()["seals"] if row["manifest_sha256"] != self.sha][0]
        diff = self.api("GET", f"/compare?old={self.sha}&new={other}", status=200).json()
        self.assertIn("a.txt", json.dumps(diff))
        self.api("GET", f"/compare?old={self.sha}", status=400)
        self.api("GET", f"/compare?old={self.sha}&new={other}&format=nope", status=404)
        job = self.wait_for(self.api("POST", "/compare/folder", {"seal": self.sha}, status=202).json()["job"]["id"])
        self.assertEqual(job["state"], "done", job)
        self.assertIn("a.txt", json.dumps(job["result"]))
        self.api("GET", f"/jobs/{job['id']}/diff/text", status=200)

    def test_authorities_settings_formats_and_health(self):
        names = [item["name"] for item in self.api("GET", "/authorities", status=200).json()["authorities"]]
        self.assertTrue(names)
        settings = self.api("GET", "/settings", status=200).json()
        self.assertIn("profiles", settings)
        formats = self.api("GET", "/formats", status=200).json()
        self.assertEqual([item["name"] for item in formats["report"]], [item.name for item in report_formats.REPORT_FORMATS])

    def test_stamp_needs_an_unchanged_manifest(self):
        self.manifest_path.write_bytes(self.manifest_path.read_bytes() + b"\n")
        answer = self.api("POST", f"/seals/{self.sha}/stamp", {"authority": "FreeTSA"}, status=409)
        self.assertIn("manifest", answer.json()["error"]["message"])


class Check(WebTestCase):
    """Files someone else gave you: a manifest, a token and maybe a root, uploaded to be checked."""

    def setUp(self):
        super().setUp()
        self.login()
        self.folder, self.manifest_path = self.sealed_and_stamped()
        self.token_path = self.manifest_path.with_suffix(".tsr")

    def upload(self, fields=(), files=None, path="/check", status=303):
        files = files if files is not None else [
            ("manifest", "given-manifest.txt", self.manifest_path.read_bytes()),
            ("token", "given.tsr", self.token_path.read_bytes()),
            ("root", "root.der", self.authority.authority.root),
        ]
        body, kind = multipart(list(fields) + [("form_token", self.form_token)], files)
        answer = self.raw("POST", path, body, {"Content-Type": kind, "Origin": f"http://{self.host}"})
        self.assertEqual(answer.status, status, answer)
        return answer

    def scratch_left(self):
        return [path.name for path in home.ensure_home().glob("web-check-*")]

    def test_with_a_folder_and_a_root_the_files_can_be_verified(self):
        job = self.wait_for(self.job_of(self.upload([("folder", str(self.folder))])))
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(job["result"]["overall"], "VERIFIED", job["result"])
        page = self.get(f"/jobs/{job['id']}").text
        self.assertIn("RESULT: VERIFIED", page)
        self.assertIn("given-manifest.txt", page)
        report = self.get(f"/jobs/{job['id']}/report/text").text
        self.assertIn("given-manifest.txt", report)
        self.assertEqual(self.scratch_left(), [])

    def test_without_a_folder_only_the_token_is_checked(self):
        page = self.get("/check").text
        self.assertIn("cannot be VERIFIED", page)
        self.assertIn("trusted for this one check only", page)
        job = self.wait_for(self.job_of(self.upload()))
        self.assertEqual(job["result"]["overall"], "INCOMPLETE", job["result"])
        self.assertIn("folder", json.dumps(job["result"]["files"]))
        self.assertEqual(self.scratch_left(), [])

    def test_without_the_root_the_fake_authority_is_not_trusted(self):
        files = [("manifest", "m.txt", self.manifest_path.read_bytes()), ("token", "t.tsr", self.token_path.read_bytes())]
        job = self.wait_for(self.job_of(self.upload([("folder", str(self.folder))], files)))
        self.assertNotEqual(job["result"]["overall"], "VERIFIED")

    def test_a_check_writes_nothing_into_the_folders_and_records_nothing(self):
        before = sorted(path.name for path in self.temp.rglob("*") if "home" not in path.parts)
        runs_before = self.api("GET", f"/seals/{self.only_seal()['manifest_sha256']}", status=200).json()["runs"]
        self.wait_for(self.job_of(self.upload([("folder", str(self.folder))])))
        after = sorted(path.name for path in self.temp.rglob("*") if "home" not in path.parts)
        self.assertEqual(before, after)
        runs_after = self.api("GET", f"/seals/{self.only_seal()['manifest_sha256']}", status=200).json()["runs"]
        self.assertEqual(runs_before, runs_after)

    def test_hostile_upload_names_are_shown_safely(self):
        files = [
            ("manifest", "..\\..\\<script>alert(1)</script>.txt", self.manifest_path.read_bytes()),
            ("token", "../../etc/passwd", self.token_path.read_bytes()),
        ]
        job = self.wait_for(self.job_of(self.upload([], files)))
        page = self.get(f"/jobs/{job['id']}").text
        self.assertNotIn("<script>alert", page)
        self.assertFalse((self.temp.parent / "etc").exists())

    def test_missing_or_empty_files_are_refused(self):
        self.upload([], [("manifest", "m.txt", b"x")], status=400)
        self.upload([], [("manifest", "m.txt", b""), ("token", "t.tsr", b"x")], status=400)
        self.assertEqual(self.scratch_left(), [])

    def test_hostile_multipart_bodies_are_refused(self):
        token = self.form_token
        bodies = [
            b"garbage",
            b"--evidence-seal-test-boundary\r\n\r\n",
            (
                b"--evidence-seal-test-boundary\r\nContent-Disposition: form-data; name=\"evil\"\r\n\r\nx\r\n"
                b"--evidence-seal-test-boundary--\r\n"
            ),
        ]
        for body in bodies:
            with self.subTest(body[:30]):
                answer = self.raw(
                    "POST",
                    "/check",
                    body,
                    {"Content-Type": "multipart/form-data; boundary=evidence-seal-test-boundary", "Origin": f"http://{self.host}", "X-Form-Token": token},
                )
                self.assertEqual(answer.status, 400, answer)
                self.assertIn("upload was refused", answer.text)

    def test_an_oversized_token_is_refused(self):
        from evidence_seal import tsp

        files = [("manifest", "m.txt", b"x"), ("token", "t.tsr", b"0" * (tsp.MAX_TOKEN_BYTES + 1))]
        answer = self.upload([], files, status=400)
        self.assertIn("limit", answer.text)

    def test_the_api_check(self):
        files = [
            ("manifest", "m.txt", self.manifest_path.read_bytes()),
            ("token", "t.tsr", self.token_path.read_bytes()),
            ("root", "root.der", self.authority.authority.root),
        ]
        body, kind = multipart([("folder", str(self.folder))], files)
        sent = {"Authorization": f"Bearer {self.server.key}", "Content-Type": kind}
        saved, self.cookie = self.cookie, None
        answer = self.raw("POST", "/api/v1/check", body, sent)
        self.cookie = saved
        self.assertEqual(answer.status, 202, answer)
        job = self.wait_for(answer.json()["job"]["id"])
        self.assertEqual(job["result"]["overall"], "VERIFIED")


class OfflineFlow(WebTestCase):
    """Seal a folder from the web, stamp it with a local test authority, verify it and download a report."""

    def setUp(self):
        super().setUp()
        self.login()
        made = local_authority.init(self.temp / "local-authority", register=False)
        self.local = LocalServer(local_authority.load(self.temp / "local-authority"), port=0).start()
        self.addCleanup(self.local.stop)
        authorities.register_test_authority("local-test", self.local.url, made.authority.root, made.authority.policy)

    def test_seal_stamp_verify_and_report(self):
        folder = self.make_folder("evidence", {"notes.txt": b"Example Org notes\n", "data/table.csv": b"a,b\n1,2\n"})
        fields = {"folder": str(folder), "purpose": "Example Org review", "profile": ""}
        self.assertIn("Seal these files", self.post("/new/preview", fields, status=200).text)
        sealed = self.wait_for(self.job_of(self.post("/new/seal", fields, status=303)))
        self.assertEqual(sealed["state"], "done", sealed)
        sha = sealed["seal"]
        page = self.get(f"/seals/{sha}").text
        self.assertIn("local-test", page)
        self.assertIn("Stamping is the only step", page)
        stamped = self.wait_for(self.job_of(self.post(f"/seals/{sha}/stamp", {"authority": "local-test", "profile": ""}, status=303)))
        self.assertEqual(stamped["state"], "done", stamped)
        self.assertIn("TEST", self.get(f"/jobs/{stamped['id']}").text)
        verified = self.wait_for(self.job_of(self.post(f"/seals/{sha}/verify", {}, status=303)))
        self.assertEqual(verified["state"], "done", verified)
        self.assertEqual(verified["result"]["verification"]["overall"], "VERIFIED", verified["result"])
        page = self.get(f"/jobs/{verified['id']}").text
        self.assertIn("RESULT: VERIFIED", page)
        self.assertIn("local test authority", page)
        report = self.get(f"/seals/{sha}/report/html")
        self.assertIn(b"VERIFIED", report.body)
        self.assertIn(f"/seals/{sha}", self.get("/").text)
        listing = self.api("GET", f"/seals/{sha}", status=200).json()
        self.assertEqual(len(listing["tokens"]), 1)
        self.assertEqual(listing["runs"][0]["overall"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
