# File formats

Everything here is plain enough to read without this tool. That is on purpose: a seal may need to be
checked long after this tool is gone.

## The native manifest, format v1

UTF-8 text, with a line feed ending every line. A carriage return anywhere means the bytes were altered.

```text
evidence-seal manifest v1
purpose: My designs before the Acme meeting
created: 2026-11-07
folder: my-work
algorithm: sha256
exclude: .git
link: shortcut.txt
special: a-fifo
files: 2
total-bytes: 373

40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880  256  data/blob.bin
1f049302d98c1c4a1dcac2bc95e86b75d52c05be57b33544f7d32e41e2235385  117  notes.txt
```

**Header.** The first line is exactly as shown. Then come `key: value` lines, and a blank line ends them.

| Key | Meaning |
|---|---|
| `purpose` | Why the seal was made, in the sealer's words. A claim. |
| `created` | `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ`. A claim. Only the token proves a date. |
| `folder` | The name of the folder that was sealed, with no path. |
| `algorithm` | Always `sha256` in v1. |
| `exclude` | One pattern per line, in the order they apply. |
| `link`, `special` | Links and special files, listed by name and not hashed. |
| `files`, `total-bytes` | The count and sum of the entries, so a removed line is noticed even with no token. |

**Entries.** Each line is the lowercase hex SHA-256, two spaces, the size in bytes, two spaces, and the
path. Paths use `/` on every system and are relative to the folder. Entries are sorted by the UTF-8
bytes of the path, so the order is the same on every system and locale.

**Escaping,** in `purpose`, `folder`, `exclude`, `link`, `special` and paths:

| Written | Means |
|---|---|
| `\\` | A backslash |
| `\n`, `\r`, `\t` | Line feed, carriage return, tab |
| `\xNN` | A control character, or one byte of a name that is not valid UTF-8 |
| `\uNNNN` | A lone surrogate, which only a Windows name can hold |

Other characters are written as themselves, in whatever Unicode form the file system gave.

**Checking by hand.** Compare the output of `sha256sum` with each entry. To check the manifest
against a token, use the `openssl` commands in the README.

## Companion files

They sit beside the manifest and share its name.

| File | What it is |
|---|---|
| `.tsr` | The token: an RFC 3161 TimeStampResp, in DER. A bare token, with `.tst`, also works. |
| `.tsq` | The request that was sent, in DER, which lets `verify` check the nonce. |
| `.ca.crt` | A copy of the root certificate from the token, in PEM. A convenience, and proof of nothing. |
| `.report.txt`, `.report.html` | The output of `report`. |
| `.replaced-YYYYMMDDTHHMMSSZ.tsr` | A token that `stamp --force` replaced, and likewise for `.tsq` and `.ca.crt`. |

## What may change, and what will not

The token covers the manifest's exact bytes, so **a manifest can never be upgraded in place**. Rewriting
one would break its proof. So:

- Every later version of this tool must keep reading format v1. `tests/fixtures/portable/golden-manifest.txt`
  and its token exist to hold that line.
- A new header key or a new kind of entry needs a new format number. Format v1 readers treat an unknown
  header as a damaged manifest, so adding one quietly is not possible.
- A tool that meets a higher format number than it knows reports the file check as NOT CHECKED, says
  which format it found, and still checks the token, which depends only on the bytes.

## JSON output

`verify --json` carries `schema_version`, now 1. Fields may be added within a schema version, and a
field is removed or changes meaning only with a new number. JSON is plain ASCII, with the exact values
kept in JSON escapes. Control characters are therefore present in the decoded values, so a program that
prints them should treat them as untrusted text. Only a run that reached a verdict prints JSON. Exit
code 2, 4 or 130 means there is none, and the message goes to standard error.

## The settings file

The optional settings file and its profiles are described in [SETTINGS.md](SETTINGS.md). Nothing in
it changes the manifest format.
