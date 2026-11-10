# Changelog

Version numbers follow semantic versioning. The manifest format has its own version, described in
[docs/FORMAT.md](docs/FORMAT.md), and it changes far less often than this tool.

## 1.1.0 (2026-11-10)

New:

- A seal library on this computer records every seal, stamp and verify run, with copies of each
  manifest, token, request and root. `library` lists, shows, imports earlier seals, verifies them
  again, checks its own copies, tags, keeps append-only notes, and writes an evidence register in
  text, CSV, JSON, Markdown, HTML or PDF. Its index has a schema version and upgrades itself after a
  dated backup.
- A settings file with named profiles, changed through `config` and `profile` without losing comments.
- An authority list (`authority`), used by `stamp --authority NAME`, whose roots `verify` and
  `report` trust.
- `test-authority`, a local timestamp authority for trying everything offline. Its tokens are marked
  as test tokens everywhere they are shown.
- `report` also writes JSON, Markdown, CSV, JUnit XML and PDF.
- `export` writes a manifest's file list for `sha256sum` and other tools, and `diff` compares two
  manifests or a manifest and a folder.
- `serve`, a web interface and JSON API on a loopback address, protected by a per-run access key.

Changed:

- All of the tool's own files live in one home folder, which `EVIDENCE_SEAL_HOME` moves.
- `verify` and `report` trust the roots in the authority list as well as the built-in fingerprints.
  `--ca` still means only the given files.

Unchanged: the manifest format is still v1, byte for byte, and `verify --json` is still schema 1.

## 1.0.0 (2026-11-07)

First version.

Commands:

- `seal` writes a byte-for-byte reproducible manifest of a folder, with ordered exclude rules,
  `--exclude-from` and a `--dry-run` that opens no file.
- `stamp` gets an RFC 3161 timestamp, checks the answer before saving it, retries failures that may
  pass, and keeps a dated copy of anything `--force` replaces.
- `verify` reports the files and the token separately, and gives VERIFIED only when every check passed.
- `show` prints what a token says.
- `report` writes one page in text or HTML, with the `openssl` commands to repeat the checks.

Behavior worth relying on:

- A seal made on Windows produces the same manifest bytes as one made on Linux from the same folder.
- No write can leave a half-written file, and an interrupted run leaves nothing behind.
- A file that changes during a seal, or that cannot be read, stops the seal.
- `seal --force` refuses to replace a manifest that has a token beside it.
- Text from files and tokens cannot fake a result line or send escape codes to a terminal.
- A manifest in a newer format comes back as NOT CHECKED and is never misread.
