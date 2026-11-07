# Changelog

Version numbers follow semantic versioning. The manifest format has its own version, described in
[docs/FORMAT.md](docs/FORMAT.md), and it changes far less often than this tool.

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
