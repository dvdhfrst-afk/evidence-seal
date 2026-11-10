"""The stylesheet and the one script, kept as text here so the package needs no data files.

They are served as files from /assets/, because the pages' Content-Security-Policy allows no inline
script or style. The script only polls a running job and updates its progress; every page works
without it.
"""

from __future__ import annotations

STYLE = """
:root {
  color-scheme: light dark;
  --text: #1d1c1a; --muted: #5b5850; --line: #cfcabf; --back: #fbfaf7; --panel: #f1efe9;
  --link: #1f4f8f; --focus: #b35c00; --pass: #1d6b3a; --fail: #a3201d; --open: #7a5200;
}
@media (prefers-color-scheme: dark) {
  :root {
    --text: #ecebe7; --muted: #b5b1a7; --line: #4a4740; --back: #1b1a18; --panel: #262420;
    --link: #8fb8ef; --focus: #ffb35c; --pass: #6fcf8f; --fail: #ff8a80; --open: #f0c060;
  }
}
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--text);
       background: var(--back); }
a { color: var(--link); }
a:focus, button:focus, input:focus, select:focus, textarea:focus, summary:focus {
  outline: 3px solid var(--focus); outline-offset: 2px; }
.skip { position: absolute; left: -999px; }
.skip:focus { left: 1rem; top: 1rem; background: var(--back); padding: 0.5rem; z-index: 2; }
header { border-bottom: 1px solid var(--line); background: var(--panel); }
header nav { max-width: 64rem; margin: 0 auto; padding: 0.5rem 1rem; display: flex; flex-wrap: wrap; gap: 0.25rem 1rem; }
header nav a { padding: 0.25rem 0; }
header nav a[aria-current="page"] { font-weight: bold; text-decoration-thickness: 3px; }
main { max-width: 64rem; margin: 0 auto; padding: 1rem; }
h1 { font-size: 1.5rem; margin: 0.5rem 0 1rem; }
h2 { font-size: 1.15rem; margin: 1.75rem 0 0.5rem; border-bottom: 1px solid var(--line); }
h3 { font-size: 1rem; margin: 1.25rem 0 0.25rem; }
.muted { color: var(--muted); }
.flash { border: 2px solid var(--line); padding: 0.5rem 0.75rem; background: var(--panel); }
.error { border: 2px solid var(--fail); padding: 0.5rem 0.75rem; }
.notice { border-left: 4px solid var(--open); padding: 0.25rem 0.75rem; background: var(--panel); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
th, td { text-align: left; vertical-align: top; padding: 0.3rem 0.5rem; border-bottom: 1px solid var(--line);
         overflow-wrap: anywhere; }
th { font-weight: 600; }
code, .mono { font-family: Consolas, Menlo, monospace; font-size: 0.9em; overflow-wrap: anywhere; }
form.inline { display: inline; }
fieldset { border: 1px solid var(--line); margin: 0.75rem 0; padding: 0.5rem 0.75rem; }
label { display: block; font-weight: 600; margin-top: 0.75rem; }
label.check { font-weight: normal; }
.help { display: block; color: var(--muted); font-size: 0.9rem; }
input[type=text], input[type=search], select, textarea { width: 100%; max-width: 40rem; padding: 0.4rem;
  font: inherit; color: var(--text); background: var(--back); border: 1px solid var(--muted); }
textarea { min-height: 5rem; }
button { font: inherit; padding: 0.4rem 0.9rem; margin: 0.75rem 0.5rem 0 0; cursor: pointer;
         border: 2px solid var(--link); background: var(--panel); color: var(--text); }
button.danger { border-color: var(--fail); }
button.small { padding: 0.1rem 0.5rem; margin: 0; font-size: 0.85rem; }
.verdict { border: 3px solid var(--line); padding: 0.5rem 1rem; margin: 1rem 0; }
.verdict h2 { border: 0; margin-top: 0.5rem; }
.verdict-verified { border-color: var(--pass); }
.verdict-failed { border-color: var(--fail); }
.verdict-incomplete { border-color: var(--open); }
.status { font-weight: bold; white-space: nowrap; }
.status-pass, .result-verified { color: var(--pass); }
.status-fail, .result-failed { color: var(--fail); }
.status-not-checked, .result-incomplete { color: var(--open); }
progress { width: 100%; max-width: 40rem; height: 1.25rem; }
.pager { display: flex; flex-wrap: wrap; gap: 1rem; margin: 0.5rem 0; }
dl.facts { display: grid; grid-template-columns: minmax(8rem, 14rem) 1fr; gap: 0.25rem 1rem; }
dl.facts dt { font-weight: 600; }
dl.facts dd { margin: 0; overflow-wrap: anywhere; }
@media (max-width: 40rem) {
  dl.facts { grid-template-columns: 1fr; }
  dl.facts dd { margin-bottom: 0.5rem; }
  th, td { padding: 0.25rem; }
}
"""

SCRIPT = """
(function () {
  "use strict";
  var box = document.querySelector("[data-job]");
  if (!box) { return; }
  var id = box.getAttribute("data-job");
  var bar = box.querySelector("progress");
  var text = box.querySelector("[data-progress-text]");
  function tick() {
    fetch("/api/v1/jobs/" + encodeURIComponent(id), {
      credentials: "same-origin", headers: {"Accept": "application/json"}, cache: "no-store"
    }).then(function (answer) {
      if (!answer.ok) { throw new Error("status " + answer.status); }
      return answer.json();
    }).then(function (job) {
      var progress = job.progress || {};
      if (bar && progress.total_bytes > 0) {
        bar.max = progress.total_bytes;
        bar.value = progress.bytes;
      }
      if (text) { text.textContent = job.progress_text; }
      if (job.state === "waiting" || job.state === "running") {
        window.setTimeout(tick, 1000);
      } else {
        window.location.reload();
      }
    }).catch(function () {
      window.setTimeout(tick, 3000);
    });
  }
  window.setTimeout(tick, 500);
}());
"""

ASSETS = {
    "style.css": ("text/css; charset=utf-8", STYLE.lstrip().encode("ascii")),
    "app.js": ("text/javascript; charset=utf-8", SCRIPT.lstrip().encode("ascii")),
}
