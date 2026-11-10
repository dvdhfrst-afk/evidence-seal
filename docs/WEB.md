# The web interface

`evidence-seal serve` opens a web interface and a JSON API to the seal library, on this computer only.
It shows the same verdicts as the command line, with the same words (VERIFIED, FAILED, INCOMPLETE)
and the same "what this does and does not show" text, and it records each verification in the
library exactly as `library verify` does. The pages work without JavaScript; the only script updates
the progress of a running job, and without it the page reloads itself every few seconds instead.

## Starting it

```bash
evidence-seal serve
```

It prints an address such as `http://127.0.0.1:53817/?key=...`. Open it in a web browser on this
computer. The key in it is this run's access key: anyone who has it can use the interface while
`serve` runs, so do not paste it anywhere. A new key is made each time `serve` starts. Press Ctrl+C
to stop it; jobs that can stop safely are cancelled, and the exit code is 130.

```bash
evidence-seal serve --port 8765 --open
```

- `--port N` listens on that port. By default the system chooses a free one.
- `--host ADDRESS` chooses another loopback address, such as `::1`. Any address that is not
  loopback is refused, so nothing on the network can reach the interface.
- `--open` opens the address in the web browser once it is listening.
- `--profile NAME` is the settings profile that sealing, stamping and checking use unless a form
  chooses another. Verifying a seal from the library uses no profile, like `library verify`.

Exit codes: 0 stopped, 2 bad arguments or a port that cannot be used, 130 stopped by Ctrl+C.

## Security model

The interface can seal, stamp and forget, so it is guarded as if every other program and web page on
this computer were hostile.

- **Loopback only.** It listens on `127.0.0.1` or another loopback address, never on the network.
- **An access key on every request.** The first visit trades the key in the address for a session
  cookie (HttpOnly, SameSite=Strict, named for the port) and moves to the same address without the
  key, so it does not stay in the address bar or the history. A program sends
  `Authorization: Bearer KEY` instead. Keys and session IDs are compared in constant time.
- **The Host header must name this server.** A request must say `Host: 127.0.0.1:PORT` (or
  `localhost:PORT`). This refuses a web page whose own name was pointed at 127.0.0.1, which is how
  DNS rebinding reaches local servers.
- **Every change is a POST** with the page's form token, and when a browser says where a request came
  from (the Origin header, or failing that Sec-Fetch-Site), it must be this page itself. Other ports
  of 127.0.0.1 count as other web pages. A program using the bearer key needs no form token.
- **No inline script or style.** Every page has a Content-Security-Policy that allows only this
  server's own style sheet and script, frames nothing and is framed by nothing. Every answer also
  carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
  and `Cache-Control: no-store`. A downloaded report gets a policy that runs no script at all.
- **Everything shown is escaped.** File names, purposes, tags, folder names and error messages come
  from manifests other people wrote, so each goes through the same display function as the command
  line, then HTML escaping.
- **Typed paths are treated as hostile.** A folder or file typed into a form must be a full local
  path. Network and device paths, `..`, control characters, alternate data streams, Windows device
  names and anything inside evidence-seal's own folder are refused before anything opens them.
- **Uploads never touch your folders.** Files uploaded to be checked are kept in a private
  temporary folder inside evidence-seal's own folder while they are checked, then removed. Their
  names are only shown, never used to open or write a file.
- **Everything is bounded:** headers, addresses, bodies, fields, uploads, connections, sessions and
  jobs. See [Limits](#limits). An oversized body is refused before any of it is read.
- **Failures are plain.** A failed job or request gives a short message and never a stack trace.

What it does not protect against:

- **Someone who has the key**, or who can read the terminal where `serve` printed it, or this
  user's browser cookies. They can do anything the interface can.
- **Other programs running as you.** They can read your files and the library directly; the
  interface adds no protection there, and none is possible from inside it.
- **Other users of this computer** who can reach loopback ports. They still need the key, but the
  traffic is plain HTTP, readable by an administrator of the computer.
- **A compromised browser or browser extension**, which sees the pages and the cookie.
- **Stamping**, which sends the manifest's hash to the authority you choose. That is the only
  network use, as on the command line, and each page says so before it happens.

## Pages

| Page | What it does |
|---|---|
| `/` Seals | Every seal in the library, newest first, with its last result and date. Search words, a tag and part of a folder path filter it; 50 a page. |
| `/seals/ID` | One seal: its header, tokens, verification history, events, tags, notes and file list (100 a page). Buttons verify it, stamp it, add or remove a tag, add a note, compare it, and forget it. Notes cannot be edited here or anywhere; `library note --withdraw` withdraws one and keeps both. The file list downloads in every export format. |
| `/seals/ID/forget` | Asks for confirmation before the seal is forgotten. Your files are never touched. |
| `/new` New seal | A dry-run preview first (what would be sealed, by which pattern something would not be, and any problem), then sealing as a job. The seal's page then offers stamping. |
| `/check` Check files I was given | Upload a manifest, its token and optionally the authority's root. Without a folder only the token is checked, and the result cannot be VERIFIED. With a folder path the files are checked too. An uploaded root is trusted for that run only. Nothing is recorded in the library. |
| `/compare` | Two seals' file lists, or a seal against its folder as it is now (a job). The difference downloads in every diff format. |
| `/jobs` and `/jobs/ID` | Running and finished jobs of this run, with live progress, a cancel button where cancelling is safe, and the result. A verification's report downloads from its job in every report format. |
| `/authorities` | The authority list, read only. Test authorities are marked TEST ONLY. |
| `/settings` | The settings file's effective values for `[defaults]` and each profile, and where each came from, read only. |

A seal's report comes from a check, so `/seals/ID/report/FORMAT` gives the report of the newest
verification of that seal in this run of `serve`, and answers 409 until there is one.

## JSON API

Every endpoint is under `/api/v1/`. Version 1 changes only by adding fields; anything that would
break a program gets a new version. Answers are JSON objects with a `schema_version`. A failure is

```json
{"error": {"code": "not_found", "message": "this seal does not exist here"}}
```

with a fitting status: 400 a bad request, 401 no key or a wrong key, 403 a cross-origin request or a
wrong form token, 404, 405, 409 a state that does not allow it, 411, 413, 414, 415, 431, 500 and 503 when
every job slot is taken. A verification is `Verification.to_dict()`, exactly as `verify --json`
prints it, and seals have the shape `library list --json` prints.

Work that hashes files or uses the network starts a job and answers 202 with the job and a
`Location` header. Poll the job until its `state` is `done`, `failed` or `cancelled`.

```text
curl -H "Authorization: Bearer KEY" http://127.0.0.1:8765/api/v1/health
{"status": "ok", "api_version": 1, "tool_version": "1.1.0"}
```

POST bodies are JSON, `application/x-www-form-urlencoded`, or for `/check` multipart/form-data.
In JSON, `true` and `false` stand for yes and no, and a list of text gives several values.

| Method and path | What it does |
|---|---|
| `GET /health` | Is it up, and which versions. |
| `GET /formats` | The format names for reports, exports and diffs. |
| `GET /seals?q=&tag=&folder=&page=` | The seals, filtered, 50 a page, with `total`, `pages` and every tag. |
| `GET /seals/ID` | One seal with its tokens, runs, events, notes and file counts. ID is the full manifest SHA-256. |
| `GET /seals/ID/files?page=` | Its file list, 100 a page. |
| `GET /seals/ID/export/FORMAT` | The file list in an export format: `sha256sum`, `bsd`, `csv` or `json`. |
| `GET /seals/ID/report/FORMAT` | The report of its newest verification in this run, or 409. |
| `POST /seals/ID/verify` | Starts a verification. Optional `folder`. The result is recorded in the library. |
| `POST /seals/ID/stamp` | Starts a stamp. `authority` names one from the list; optional `profile`. Uses the network. |
| `POST /seals/ID/tags` | Adds `tag`. |
| `POST /seals/ID/untag` | Removes `tag`. |
| `POST /seals/ID/notes` | Adds a note with `text`, as `library note` does, and answers its `note` number. `GET /seals/ID` lists the notes. |
| `POST /seals/ID/forget` | Forgets the seal. Needs `confirm` set to true. |
| `POST /seal` | Seals `folder` with `purpose`, optional `exclude` (a list), `out` and `profile`. With `dry_run` true it answers the preview instead. |
| `GET /jobs` | This run's jobs, newest first. |
| `GET /jobs/ID` | One job. |
| `POST /jobs/ID/cancel` | Asks a job to stop. 409 if it has finished or cannot stop safely. |
| `GET /jobs/ID/report/FORMAT` | The report of a verify or check job, in any report format. |
| `GET /jobs/ID/diff/FORMAT` | The difference from a compare job, in any diff format. |
| `GET /compare?old=ID&new=ID&format=` | Two seals' difference, JSON by default. |
| `POST /compare/folder` | Starts comparing `seal` against `folder`, or where it was last seen. |
| `POST /check` | Starts a check of an uploaded `manifest` and `token`, optional `root`, `folder` and `profile`. |
| `GET /authorities` | The authority list. |
| `GET /settings` | The effective settings of `[defaults]` and each profile, with their sources. |

A job looks like this:

```json
{
  "schema_version": 1,
  "job": {
    "id": "3f0c9a1e5b7d4c2a8e6f1b0d9c7a5e3f",
    "kind": "verify",
    "title": "Verify seal 5ea307c1d2e4",
    "seal": "5ea307c1d2e4...",
    "state": "running",
    "created": "2026-03-01T12:00:00Z",
    "started": "2026-03-01T12:00:00Z",
    "finished": null,
    "cancellable": true,
    "cancel_requested": false,
    "progress": {"files": 120, "total_files": 400, "bytes": 52428800, "total_bytes": 209715200},
    "progress_text": "Checked 120 of 400 files, 50.0 MB of 200.0 MB.",
    "messages": [],
    "error": null,
    "result": null
  }
}
```

A finished verify job's `result` is the same object `library verify --json` prints for one seal,
with the verification under `verification`. A check job's `result` is the verification itself. A
seal job's `result` names the manifest and its counts, and a stamp job's names the token and what
it says.

Sealing a folder from a program, first as a dry run:

```text
curl -H "Authorization: Bearer KEY" -H "Content-Type: application/json" -d "{\"folder\": \"/home/you/work\", \"purpose\": \"Example Org review\", \"dry_run\": true}" http://127.0.0.1:8765/api/v1/seal
```

Checking files you were given, with the folder:

```text
curl -H "Authorization: Bearer KEY" -F manifest=@work-manifest.txt -F token=@work-manifest.tsr -F root=@root.crt -F folder=/home/you/work http://127.0.0.1:8765/api/v1/check
```

## Limits

| What | Limit |
|---|---|
| Request headers | 50; a Cookie header over 8 KB is ignored |
| Address | 8192 characters |
| A form or JSON body | 64 KB, at most 64 fields of at most 16 KB each |
| An upload to `/check` | 40 MB in all: a manifest of 32 MB, a token of 4 MB and a root of 256 KB |
| A typed path | 4096 characters |
| Jobs waiting or running at once | 4; more answers 503 and starts nothing |
| Finished jobs remembered | the newest 100, for this run only |
| Browser sessions | 32; the oldest is dropped |
| Connections at once | 32 |
| A connection that sends nothing | closed after 30 seconds |

Jobs, sessions and reports live in memory and are gone when `serve` stops. What is recorded in the
library stays, as from the command line.
