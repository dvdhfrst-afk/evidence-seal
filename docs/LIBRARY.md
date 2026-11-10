# The seal library

People who seal often lose track: which folder was sealed when, where the token went, and whether it
still verifies. The library keeps that record for you. Every `seal`, `stamp`, `verify` and `report`
writes a short entry, and keeps a copy of the manifest, token, request and root certificate it saw, so
a seal can still be checked after its files beside the folder are lost.

The library only ever writes inside its own folder. It never moves, changes or deletes your files.

## What is kept, and where

Everything lives in the `library` folder inside evidence-seal's home folder. `library where` prints
the exact place. By default the home folder is `%APPDATA%\evidence-seal` on Windows,
`~/Library/Application Support/evidence-seal` on macOS and `~/.local/share/evidence-seal` elsewhere.

| Path | What it is |
|---|---|
| `library/index.sqlite3` | The index, an SQLite database. |
| `library/objects/ab/abcd...` | One copy of each manifest, token, request and root certificate, named by the SHA-256 of its bytes. |
| `library/index.sqlite3.backup-schema1-YYYYMMDDTHHMMSSZ` | A copy of the index made just before an upgrade. |

The index holds, for each seal: the manifest's SHA-256 (which is the seal's ID), its purpose and
created field, the folder name, file count and total size, whether it is a native or hand-made
manifest, and the paths where the manifest and the folder were last seen. For each token: its own
SHA-256, its time, the authority named in it, its serial number, whether it is the current token or
one that `stamp --force` replaced, and where it was last seen. For each verification run: when, the
result, the exit code, each check's title and status, and the folder used. It also holds your tags,
your notes, and a journal of events (sealed, stamped, verified, imported, tagged, untagged, noted,
withdrew, forgotten) with the version of evidence-seal that wrote each one.

Each copy is written to a temporary file first and then renamed, so a crash cannot leave half a copy.
Every time a copy is read it is checked against its name, and a copy that no longer matches is refused.

## Privacy

The library is private to this computer and nothing in it is ever sent anywhere. It does hold
personal information: the paths of your folders and files, your purpose statements, and copies of
your manifests, which list the name and hash of every sealed file. Anyone who can read your home
folder can read the library. On Linux and macOS the folder is made readable only by you.

If you do not want this record, turn the library off, and delete the `library` folder to remove what
it already holds.

## Turning it off

For one command, add `--no-library` to `seal`, `stamp`, `verify` or `report`:

```bash
python -m evidence_seal verify examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt --no-library
```

For every command, set the environment variable `EVIDENCE_SEAL_LIBRARY` to `off` (`no`, `false`
and `0` work too). Turning recording off deletes nothing. `library` commands still read what is there.

## When the library has a problem

A library problem never changes what a command does. The seal, token, verdict, output and exit code
are exactly what they would be with `--no-library`, and one line on standard error says what was not
recorded:

```text
warning: the seal library did not record this run: the library index ... is damaged and cannot be read (...). Nothing else was affected.
```

## Moving it, and backing it up

To keep the library somewhere else, set `EVIDENCE_SEAL_HOME`. That moves all of evidence-seal's own
files, the library included. To move an existing library, copy the whole `library` folder into the
new home folder while no evidence-seal command is running, then set the variable.

To back it up, copy the whole `library` folder while no evidence-seal command is running. The copies
in `objects` are ordinary files, and the index is an ordinary SQLite file. After restoring a backup,
run `library check`.

Two commands running at the same moment do not damage the library. Each one writes in a short
transaction, and the second waits up to 15 seconds for the first.

## Commands

Each takes `--help`. An `ID` is the start of the manifest's SHA-256, at least 6 hex digits, as
`library list` shows it, or the path of a manifest file. A prefix that fits more than one seal is
refused, and the error lists the seals it fits.

**List** every seal, oldest first, with its token time and its last verification:

```bash
python -m evidence_seal library list
```

`--folder PATH` shows only the seals whose folder was last seen at that path, `--tag TAG` only those
with that tag, and `--json` prints the list as JSON.

**Show** everything known about one seal: its tokens, every verification run and every event.

```bash
python -m evidence_seal library show 5ea307
```

**Import** seals made before the library existed, or with recording off. Give manifest files or
folders, and add `--recursive` to look in the folders inside them too. `--dry-run` says what would be
added and writes nothing.

```bash
python -m evidence_seal library import examples/sealed --dry-run
```

A native manifest is recognized by its first line. Another file counts as a hand-made manifest only
when a token beside it covers it, or when you name the file itself. The tokens, requests and root
copies beside a manifest come in with it, including tokens that `stamp --force` kept. Every file is
read as untrusted: a damaged manifest, a token that does not cover its manifest, or a file too large
to be what it claims is skipped and the reason is printed. Links are never followed, and import looks
through at most 200,000 files and folders, 32 levels deep. Import never writes beside your files. It
exits 0 when every manifest it found was added or already known, and 1 when anything was skipped.

**Verify** seals from the library's own copies of the manifest and the current token, against the
folder where the files last matched. Each run is recorded. `--all` verifies every seal, `--folder DIR`
checks one seal against another folder (and remembers it if the files match), and `--json` prints
every detail.

```bash
python -m evidence_seal library verify --all --ca examples/sealed/test-authority-root.crt
```

As with `verify`, a root certificate is trusted only when it is built in or given with `--ca`. The
library's copy of the root from the token is kept for reference and never trusted by itself. A seal
whose folder is gone is INCOMPLETE, with the reason. The exit code is the worst result: 1 if any seal
FAILED, 3 if any is INCOMPLETE, and 0 only when every seal is VERIFIED.

**Check** that the library itself is sound: every copy matches its hash, every copy the index refers to
exists, no copy is left unused, and SQLite's integrity check passes. It also checks the notes: each
seal's notes are numbered 1, 2, 3 with no gap, each withdrawal names an earlier note that no other
withdrawal names, every note's text is text a note can hold, and the rule that refuses changes to notes
is still in the index. It changes nothing, and exits 0 when the library is sound and 1 otherwise,
listing each problem.

```bash
python -m evidence_seal library check
```

**Forget** a seal: remove it from the index, with the copies no other seal uses. It asks first on a
terminal, and needs `--yes` otherwise. The seal's notes go with it, and the question says how many.
Your manifest, tokens and folder are never touched. The journal keeps one line saying the seal was
forgotten.

```bash
python -m evidence_seal library forget 5ea307 --yes
```

**Tag** a seal, or remove a tag. A tag is 1 to 64 printable characters.

```bash
python -m evidence_seal library tag 5ea307 contract-review
```

```bash
python -m evidence_seal library untag 5ea307 contract-review
```

**Note** why a seal was made, who handled it and what happened next. See [Notes](#notes) below.

```bash
python -m evidence_seal library note 5ea307 "Received from Example Org on a USB drive, sealed on arrival."
```

**Notes** lists a seal's notes, oldest first. `--json` prints them as JSON.

```bash
python -m evidence_seal library notes 5ea307
```

**Register** writes one document listing every chosen seal. See [The evidence register](#the-evidence-register)
below.

```bash
python -m evidence_seal library register --format pdf --out register.pdf
```

**Log** prints the journal, newest first: everything, or one seal's events with an ID. `--limit N`
shows at most N events (20 by default).

```bash
python -m evidence_seal library log --limit 50
```

**Where** prints where the library is, how large it is, and whether recording is on.

```bash
python -m evidence_seal library where
```

## Notes

A note is a dated line or paragraph on one seal, in your own words: why it was sealed, who handled it,
where it went, what happened next. Each note keeps its number (1 for a seal's first note, and one more
for each after it), the time it was added in UTC, the version of evidence-seal that added it, and its
text exactly as given. A note can be up to 4,000 characters, and a seal can hold up to 1,000 notes,
withdrawals included.

Line breaks are kept, so a note can run over several lines when your shell lets you type them inside
quotes. Windows line ends are kept as plain line feeds. Anything else that could act on a screen is
refused with a plain error and nothing is written: control characters such as tabs, bells and
terminal escape codes, and formatting characters such as those that reverse how a line displays.
Markup, formulas and text in any script are kept as written, and every format shows them only in a
form that format cannot act on.

Notes are append-only. Nothing in evidence-seal changes or deletes a note, and the index itself
refuses any change to one. A note that turns out wrong is **withdrawn**, with the reason:

```bash
python -m evidence_seal library note 5ea307 --withdraw 2 --reason "Entered on the wrong seal, see note 3 of 1f9c02."
```

The withdrawal is a note of its own, with its own number and time, that names the note it withdraws.
The withdrawn note keeps its original text and is shown marked as withdrawn, so the record says what
was written, when it was taken back, and why. A note can be withdrawn once, and a withdrawal cannot
itself be withdrawn: add a new note instead.

```text
Notes on seal 5ea307...:
  Note 1, 2026-11-09T09:14:02Z, evidence-seal 1.0.0
      Received from Example Org on a USB drive, sealed on arrival.
  Note 2, 2026-11-09T09:20:45Z, evidence-seal 1.0.0, WITHDRAWN by note 3
      Copy sent to the review desk.
  Note 3, 2026-11-09T10:02:11Z, evidence-seal 1.0.0, withdrawing note 2
      Entered on the wrong seal, see note 3 of 1f9c02.
```

Every note and withdrawal is also written to the journal, as a `noted` or `withdrew` event, and
`library show` lists the notes, in its text and in its JSON (`notes`, each with `number`, `at`,
`tool_version`, `text`, `withdraws` and `withdrawn_by`). `library forget` removes a seal's notes with
the seal, after the same question. `library check` reports a gap in a seal's note numbers, since a gap
means the index was changed outside evidence-seal.

Notes are a record kept on this computer, not proof. Anyone who can write to the index could remove
the newest note without leaving a gap, so a note shows what was recorded here, not that nothing else
was.

## The evidence register

People who seal evidence are asked for a list of everything they sealed. `library register` writes
it: one document listing every chosen seal with

- its short ID and full ID (the full ID is the SHA-256 of the manifest),
- the purpose and the created claim from the manifest, and its folder name,
- where its folder and manifest were last seen,
- how many files it lists, and their total size,
- its current token's time, authority and serial number, and every token `stamp --force` replaced,
- the result and date of the last verification recorded here, and which command ran it,
- its tags, and all of its notes, withdrawn ones shown as withdrawn.

It also says plainly what the register is, and how anyone can check each seal without it.

```bash
python -m evidence_seal library register --tag contract-review --since 2026-01-01 --until 2026-06-30 --format markdown --out register.md
```

**Choosing seals.** With no options every seal is listed. `--tag TAG` lists only seals with that tag,
and `--folder PATH` only those whose folder was last seen at that path. `--since DATE` and
`--until DATE` take a day as `YYYY-MM-DD`, both days included, and compare it with each seal's date:
the time in its current token, or, for a seal with no token, the created claim in its manifest. A seal
with neither is not listed when either option is given. The options combine.

**Order.** Seals are listed by their date, oldest first, then by full ID. A seal with no date comes
last. The order depends only on what the library holds, never on when a seal was added to it.

**Formats.** `--format` picks one; `text` is the default.

| Format | What it is |
|---|---|
| `text` | Plain text, one block per seal, for reading or printing. |
| `csv` | One row per seal, for a spreadsheet. Columns: number, id, manifest_sha256, purpose, created, folder_name, folder_path, manifest_path, file_count, total_bytes, token_time, authority, serial, replaced_tokens, last_result, last_checked, tags, notes. Several replaced tokens, tags or notes share a cell, separated by ` \| `, and a line break in a note is written as `\x0a`. A cell that a spreadsheet would run as a formula starts with an apostrophe. The CSV holds only the table, so the statement below goes to standard error. |
| `json` | Everything, with exact values, in plain ASCII: `register_schema` (1), `tool_version`, `library_as_of`, `chosen`, `count`, `order`, `what_this_is`, `check_each_seal`, and `seals`, one object per seal with its `token`, `replaced_tokens`, `last_verification`, `tags` and `notes`. |
| `markdown` | For a code hosting site or a ticket. Any value that is not plain words is shown as code, so it cannot become markup, a link or HTML. |
| `html` | One web page, also for printing. Every value is escaped. |
| `pdf` | A PDF to print or attach, written by the same PDF writer as `report`. Characters its fonts cannot show are written as a backslash code such as `\u4e2d`, and the PDF says so. |

`--out FILE` writes the register to a new file, and `--force` replaces one that exists. Without
`--out`, or with `--out -`, it goes to standard output. A PDF is never written to a terminal. The
register is never written inside the library folder, and never over a manifest or token the library
knows, even with `--force`.

The same library content always gives the same bytes. The register does not print the time it was
made; it says instead when the newest entry in the library was recorded, so two registers from the
same library are identical and a newer one is easy to tell apart.

**What the register is not.** The register is an index made from the library on the computer that
wrote it. It checks nothing when it is written and proves nothing by itself: anyone could edit it. The
last verification it shows is what this computer recorded, not a check made now. Purposes, created
dates, folder names, tags and notes are what people wrote, not proof. The proof of each seal is its
manifest and its token, and every format ends with how to check them independently:

1. `openssl dgst -sha256 MANIFEST` must print the entry's full ID, which ties the manifest file to it.
2. `evidence-seal verify MANIFEST --folder FOLDER --ca ROOT` checks the whole seal, files included.
3. Without evidence-seal: get the authority's root certificate from the authority, compare its
   fingerprint with `openssl x509 -in ROOT -noout -fingerprint -sha256`, check the token with
   `openssl ts -verify -data MANIFEST -in TOKEN -CAfile ROOT`, read it with
   `openssl ts -reply -in TOKEN -text`, and check any file with `openssl dgst -sha256 FILE`. A bare
   token (a `.tst` file) needs `-token_in` after `TOKEN`.

The register includes the paths where folders and manifests were last seen on this computer, and the
notes you wrote. Read it before you hand it to someone.

## What each command records

- `seal` records the new seal and the folder it sealed. A dry run records nothing.
- `stamp` records the token with its request and root copy. With `--force`, the token it replaced is
  recorded as replaced, at the path of the copy `stamp` kept. A manifest the library did not know is
  added first.
- `verify` and `report` record the run. A seal or token the library did not know is added, as long as
  the token covers the manifest. The folder is remembered only when its files matched, so checking a
  different folder that fails does not lose track of the right one.

## Limits

A manifest copy can be up to 256 MB, a token 4 MB, and a request or root copy 1 MB. A larger file is
not kept, which is a warning and never a failure of the command.

## Schema versions and upgrades

The index's schema version is stored in SQLite's `PRAGMA user_version`. This version of evidence-seal
writes schema 1.

When a newer evidence-seal needs a newer schema, it upgrades the index the first time it opens it. It
first copies the index to `index.sqlite3.backup-schemaN-YYYYMMDDTHHMMSSZ` beside it, then applies
every step in one transaction. If any step fails, or the computer stops partway, the index stays
exactly at its old schema, the backup is kept, and the error names both.

An index with a newer schema than this evidence-seal knows is refused and never written: use the
newer evidence-seal, or `--no-library`. An index that is damaged, or a file that is not an
evidence-seal library, is refused with a message that names the file and says nothing was changed.
