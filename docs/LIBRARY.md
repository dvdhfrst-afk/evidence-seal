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
and a journal of events (sealed, stamped, verified, imported, tagged, untagged, forgotten) with the
version of evidence-seal that wrote each one.

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
exists, no copy is left unused, and SQLite's integrity check passes. It changes nothing, and exits 0
when the library is sound and 1 otherwise, listing each problem.

```bash
python -m evidence_seal library check
```

**Forget** a seal: remove it from the index, with the copies no other seal uses. It asks first on a
terminal, and needs `--yes` otherwise. Your manifest, tokens and folder are never touched. The journal
keeps one line saying the seal was forgotten.

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

**Log** prints the journal, newest first: everything, or one seal's events with an ID. `--limit N`
shows at most N events (20 by default).

```bash
python -m evidence_seal library log --limit 50
```

**Where** prints where the library is, how large it is, and whether recording is on.

```bash
python -m evidence_seal library where
```

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
