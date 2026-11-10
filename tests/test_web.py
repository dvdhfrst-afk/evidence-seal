"""The web interface's HTML pages, through a real server in this process."""

import json
import re
import unittest

from evidence_seal import authorities, library, local_authority, manifest
from tests.support import run_cli
from tests.web_support import WebTestCase

HOSTILE = '<script>alert(1)</script>"&\''


class Pages(WebTestCase):
    def setUp(self):
        super().setUp()
        self.login()

    def sealed(self, name="work"):
        folder, manifest_path = self.sealed_and_stamped(name)
        return folder, manifest_path, self.only_seal()["manifest_sha256"]

    def test_every_read_only_page_answers(self):
        for path in ("/", "/new", "/check", "/compare", "/jobs", "/authorities", "/settings"):
            with self.subTest(path):
                answer = self.get(path)
                self.assertIn("text/html", answer.headers["content-type"])
                self.assertIn('<a class="skip" href="#main">', answer.text)
                self.assertIn('href="/assets/style.css"', answer.text)

    def test_assets_are_files_and_pages_have_no_inline_script_or_style(self):
        css = self.get("/assets/style.css")
        self.assertEqual(css.headers["content-type"], "text/css; charset=utf-8")
        script = self.get("/assets/app.js")
        self.assertIn("javascript", script.headers["content-type"])
        for path in ("/", "/new", "/check", "/settings"):
            text = self.get(path).text
            self.assertNotIn("<style", text)
            self.assertNotIn(" style=", text)
            self.assertNotIn("<script>", text)
            self.assertIsNone(re.search(r"<[^>]* on[a-z]+=", text), path)

    def test_overview_lists_seals_with_their_last_result(self):
        folder, _, sha = self.sealed()
        text = self.get("/").text
        self.assertIn(sha[:12], text)
        self.assertIn("purpose of work", text)
        self.assertIn(f"/seals/{sha}", text)

    def test_overview_filters(self):
        self.sealed_and_stamped("alpha")
        self.sealed_and_stamped("beta")
        with self.open() as opened:
            beta = [row for row in opened.seals() if "beta" in row["purpose"]][0]["manifest_sha256"]
            opened.tag(beta, "court")
        text = self.get("/?q=alpha").text
        self.assertIn("purpose of alpha", text)
        self.assertNotIn("purpose of beta", text)
        text = self.get("/?tag=court").text
        self.assertIn("purpose of beta", text)
        self.assertNotIn("purpose of alpha", text)
        text = self.get("/?folder=nowhere-at-all").text
        self.assertNotIn("purpose of", text)

    def test_seal_page_shows_header_tokens_history_and_files(self):
        _, _, sha = self.sealed()
        text = self.get(f"/seals/{sha}").text
        for part in ("purpose of work", "a.txt", "sub/b.bin", "Tokens", "Verification history", "Events", "Verify", "Stamping is the only step"):
            self.assertIn(part, text)
        self.assertIn(f'action="/seals/{sha}/verify"', text)
        self.assertIn(f"/seals/{sha}/export/csv", text)

    def test_unknown_seal_and_short_ids_are_not_found(self):
        self.get("/seals/" + "0" * 64, status=404)
        self.get("/seals/abc", status=404)
        self.get("/seals/..%2f..%2fetc", status=404)
        self.get("/no-such-page", status=404)

    def test_tags_are_added_and_removed(self):
        _, _, sha = self.sealed()
        answer = self.post(f"/seals/{sha}/tags", {"tag": "court"}, status=303)
        self.assertEqual(answer.headers["location"], f"/seals/{sha}")
        with self.open() as opened:
            self.assertEqual(opened.seal(sha)["tags"], ["court"])
        self.post(f"/seals/{sha}/untag", {"tag": "court"}, status=303)
        with self.open() as opened:
            self.assertEqual(opened.seal(sha)["tags"], [])
        answer = self.post(f"/seals/{sha}/tags", {"tag": "bad\nline"}, status=400)
        self.assertIn("tag", answer.text)

    def test_forget_needs_a_confirmation(self):
        _, _, sha = self.sealed()
        page = self.get(f"/seals/{sha}/forget").text
        self.assertIn('name="confirm"', page)
        self.post(f"/seals/{sha}/forget", {}, status=400)
        with self.open() as opened:
            self.assertIsNotNone(opened.seal(sha))
        answer = self.post(f"/seals/{sha}/forget", {"confirm": "yes"}, status=200)
        self.assertIn("forgotten", answer.text)
        with self.open() as opened:
            self.assertIsNone(opened.seal(sha))

    def test_exports_download_in_every_format(self):
        from evidence_seal import exporting

        _, _, sha = self.sealed()
        for name in exporting.EXPORT_FORMATS:
            with self.subTest(name):
                answer = self.get(f"/seals/{sha}/export/{name}")
                self.assertIn("attachment", answer.headers["content-disposition"])
                self.assertIn("sandbox", answer.headers["content-security-policy"])
                self.assertIn(b"a.txt", answer.body)
        self.get(f"/seals/{sha}/export/nope", status=404)

    def test_verify_from_the_page_then_download_every_report(self):
        from evidence_seal import report_formats

        _, _, sha = self.sealed()
        self.get(f"/seals/{sha}/report/text", status=409)
        answer = self.post(f"/seals/{sha}/verify", {"folder": ""}, status=303)
        job = self.wait_for(self.job_of(answer))
        self.assertEqual(job["state"], "done", job)
        page = self.get(f"/jobs/{job['id']}").text
        self.assertIn("RESULT:", page)
        self.assertIn("What this", page)
        for item in report_formats.REPORT_FORMATS:
            with self.subTest(item.name):
                for path in (f"/seals/{sha}/report/{item.name}", f"/jobs/{job['id']}/report/{item.name}"):
                    answer = self.get(path)
                    self.assertTrue(answer.body)
                    self.assertIn("attachment", answer.headers["content-disposition"])
        with self.open() as opened:
            runs = opened.runs(sha)
        self.assertEqual(len(runs), 1)

    def test_verify_of_a_changed_folder_fails_and_is_recorded(self):
        folder, _, sha = self.sealed()
        (folder / "a.txt").write_bytes(b"changed\n")
        answer = self.post(f"/seals/{sha}/verify", {}, status=303)
        job = self.wait_for(self.job_of(answer))
        self.assertEqual(job["result"]["verification"]["overall"], "FAILED")
        self.assertIn("a.txt", self.get(f"/jobs/{job['id']}").text)
        with self.open() as opened:
            self.assertEqual(opened.runs(sha)[0]["overall"], "FAILED")

    def test_new_seal_previews_then_seals(self):
        folder = self.make_folder("fresh")
        fields = {"folder": str(folder), "purpose": "Example Org review", "exclude": "*.bin", "out": "", "profile": ""}
        preview = self.post("/new/preview", fields, status=200).text
        self.assertIn("a.txt", preview)
        self.assertIn("*.bin", preview)
        self.assertIn("Stamping is the only step", preview)
        self.assertEqual([path.name for path in self.temp.glob("fresh-manifest*")], [])
        answer = self.post("/new/seal", fields, status=303)
        job = self.wait_for(self.job_of(answer))
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(job["result"]["file_count"], 1)
        sha = job["seal"]
        with self.open() as opened:
            self.assertEqual(opened.seal(sha)["purpose"], "Example Org review")

    def test_new_seal_reports_a_bad_folder_on_the_form(self):
        answer = self.post("/new/preview", {"folder": str(self.temp / "missing"), "purpose": "x"}, status=400)
        self.assertIn("missing", answer.text)
        self.assertIn('name="folder"', answer.text)
        answer = self.post("/new/preview", {"folder": "relative/path", "purpose": "x"}, status=400)
        self.assertIn("full path", answer.text)

    def test_compare_two_seals_and_a_seal_against_its_folder(self):
        folder, _, sha = self.sealed()
        (folder / "a.txt").write_bytes(b"other\n")
        second = self.seal(folder, "second.txt")
        with self.open() as opened:
            other = [row["manifest_sha256"] for row in opened.seals() if row["manifest_sha256"] != sha][0]
        text = self.get(f"/compare?old={sha}&new={other}").text
        self.assertIn("a.txt", text)
        self.assertIn("changed", text.lower())
        download = self.get(f"/compare/download/json?old={sha}&new={other}")
        self.assertIn("attachment", download.headers["content-disposition"])
        self.assertTrue(json.loads(download.body))
        answer = self.post("/compare/folder", {"seal": sha, "folder": ""}, status=303)
        job = self.wait_for(self.job_of(answer))
        self.assertEqual(job["state"], "done", job)
        self.assertIn("a.txt", self.get(f"/jobs/{job['id']}").text)
        self.get(f"/jobs/{job['id']}/diff/text")
        self.assertTrue(second.exists())

    def test_authorities_page_marks_test_authorities(self):
        authority = local_authority.init(self.temp / "local", register=False)
        authorities.register_test_authority("local-test", "http://127.0.0.1:1/", authority.authority.root, authority.authority.policy)
        text = self.get("/authorities").text
        self.assertIn("local-test", text)
        self.assertIn("TEST", text)

    def test_settings_page_shows_where_values_came_from(self):
        code, _, err = run_cli("config", "set", "report-format", "html")
        self.assertEqual(code, 0, err)
        text = self.get("/settings").text
        self.assertIn("report-format", text)
        self.assertIn("html", text)
        self.assertIn("built-in", text)


class Escaping(WebTestCase):
    """Names and purposes come from manifests other people wrote, so every one is escaped."""

    def setUp(self):
        super().setUp()
        self.login()

    def hostile_seal(self):
        """A seal whose purpose, folder name and file names are all markup. No such files exist."""
        rows = [(f"{HOSTILE}.txt", "0" * 64, 2), ("plain.txt", "1" * 64, 2)]
        data = manifest.render(rows, HOSTILE, "2026-01-02", HOSTILE)
        path = self.write("hostile-manifest.txt", data)
        self.make_folder("empty", {"other.txt": b"x\n"})
        library.record_seal(path, self.temp / "empty")
        sha = self.only_seal()["manifest_sha256"]
        with self.open() as opened:
            opened.tag(sha, "<i>tag</i>")
        return sha

    def assertEscaped(self, text):
        self.assertNotIn("<script>alert", text)
        self.assertNotIn("<i>tag", text)

    def test_hostile_names_and_purposes_are_escaped_everywhere(self):
        sha = self.hostile_seal()
        pages = ["/", f"/seals/{sha}", f"/seals/{sha}/forget", f"/compare?old={sha}&new={sha}", "/compare", "/?q=" + "%3Cscript%3E"]
        for path in pages:
            with self.subTest(path):
                text = self.get(path).text
                self.assertEscaped(text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.get(f"/seals/{sha}").text)
        answer = self.post(f"/seals/{sha}/verify", {}, status=303)
        job = self.wait_for(self.job_of(answer))
        self.assertEqual(job["state"], "done", job)
        text = self.get(f"/jobs/{job['id']}").text
        self.assertEscaped(text)
        self.assertIn("&lt;script&gt;", text)
        self.assertEscaped(self.get("/jobs").text)
        report = self.get(f"/jobs/{job['id']}/report/html").text
        self.assertEscaped(report)

    def test_hostile_text_in_an_error_is_escaped(self):
        answer = self.post("/new/preview", {"folder": "C:/<script>alert(1)</script>", "purpose": HOSTILE}, status=400)
        self.assertEscaped(answer.text)
        answer = self.post("/new/preview", {"folder": "/<script>alert(1)</script>", "purpose": HOSTILE}, status=400)
        self.assertEscaped(answer.text)
        self.assertEscaped(self.get("/?q=%3Cscript%3Ealert(1)%3C/script%3E&folder=%3Ci%3Etag").text)


if __name__ == "__main__":
    unittest.main()
