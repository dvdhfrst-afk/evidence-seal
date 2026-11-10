# Reports, exports and comparisons

Three commands turn a seal into something other people and other programs can use:

- `report` runs the same checks as `verify` and writes them in one of seven formats.
- `export` writes a manifest's file list in forms other tools read, such as `sha256sum -c`.
- `diff` compares two file lists: two manifests, or a manifest and a folder hashed now.

None of them is a proof by itself. The proof is the manifest and its token. A report says what a
check found, and anyone can repeat that check. An export and a comparison look only at file lists,
and they check no token and prove no date.

## Report formats

```bash
python -m evidence_seal report examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt --format pdf
```

| `--format` | File written beside the manifest | For |
|---|---|---|
| `text` (default) | `NAME.report.txt` | One page of plain text. |
| `html` | `NAME.report.html` | One web page, which also prints well. |
| `json` | `NAME.report.json` | Programs: the verify JSON plus the claims and the commands. |
| `markdown` | `NAME.report.md` | A code hosting site, a ticket or a pull request. |
| `csv` | `NAME.report.csv` | A spreadsheet: one row per file. |
| `junit` | `NAME.report.junit.xml` | A CI (continuous integration) system: one test per check. |
| `pdf` | `NAME.report.pdf` | Printing, or attaching to a letter. |

`report` takes the same options and gives the same exit codes as `verify`. `--out FILE` writes
somewhere else, and `--out -` writes to standard output. Text formats reach a pipe or a file byte for
byte. A terminal gets them with control characters shown as escapes, and never gets a PDF, which
would garble it, so send that to a file. Without `--force` no existing report is replaced, and a report
never replaces the manifest, the token, the saved request, a root or any certificate the command
names.

Every report file name above counts as one of the manifest's own files. `seal` leaves them out when
the manifest sits inside the sealed folder, and `verify` never counts them as added files.

### What every format says

Every format carries the same things as the text report: the result and a sentence explaining it,
what is claimed (the manifest, its purpose and created field, the token's time, authority, policy and
serial number), each check as PASS, FAIL or NOT CHECKED with its detail, the notes, the `openssl`
commands to repeat the checks, and what the proof shows, does not show and depends on.

Names, purposes and certificate text come from outside, and each format shows them only in a form it
cannot act on. A file name cannot add markup to a Markdown page, a formula to a spreadsheet, an
element to XML, or a line of its own to text.

### text and html

The page the tool has always written. These two are byte for byte what earlier versions wrote.

### json

ASCII JSON with the exact values kept in JSON escapes, so control characters are present in the decoded
values and a program that prints them should treat them as untrusted text.

| Field | Meaning |
|---|---|
| `report_schema` | The version of this layout, now 1. |
| `result` | `VERIFIED`, `FAILED` or `INCOMPLETE`. |
| `summary` | The sentence explaining the result. |
| `claims` | A list of `{"label", "value"}` pairs, as the text report prints them under WHAT IS CLAIMED. |
| `commands` | A list of `{"step", "explanation", "command"}`. `command` is null for a step that only explains. |
| `shows`, `does_not_show`, `depends_on` | Lists of sentences. |
| `verification` | Exactly what `verify --json` prints, with its own `schema_version`. |

**What is stable.** Fields may be added while `report_schema` stays 1. A field is removed, renamed or
given another meaning only with a new number. The `verification` object follows the promise for the
verify JSON in [FORMAT.md](FORMAT.md#json-output). The wording of `summary`, the `claims` labels and
the `commands` is for people and may change.

### markdown

Headings, a list of claims, a table of checks and the commands in fenced code blocks. Plain words from
outside appear as they are. Anything else (markup characters, a web address, an emoji code, a backslash)
appears inside an inline code span, where Markdown reads nothing, and a pipe inside a table cell is
escaped so the table keeps its columns. The commands sit in fenced blocks whose fence is longer than any
run of backticks inside. The page ends by saying it is a summary that proves nothing by itself.

### csv

UTF-8 without a byte order mark, with a CRLF (carriage return and line feed) at the end of every line,
as RFC 4180 has it. One header row, then one row per file:

| Column | Meaning |
|---|---|
| `path` | The path as the manifest writes it, with its escapes: `\\` for a backslash, `\n` for a line feed, `\xNN` for other control characters and for bytes of a name that is not valid UTF-8. |
| `outcome` | `unchanged`, `changed`, `missing`, `added`, `moved`, `unreadable`, or `not checked` when the folder was not compared. |
| `found_path` | For `moved`, the name that now holds the same bytes. For a match under another Unicode form of the same name, that form. Otherwise empty. |
| `algorithm` | The hash the manifest used, `SHA-256` for every native manifest. Empty for an added file. |
| `expected_hash` | From the manifest. |
| `found_hash` | From the file now. Empty when the file was not hashed: it is missing, added, unreadable, or its size already differs. |
| `expected_size` | From the manifest, when it records one. |
| `found_size` | From the file now, when there is one. |

A `moved` row stands for both a missing name and an added name, which `verify` counts separately.
Links and special files appear by name, with no hash or size.

**Spreadsheet formulas.** A spreadsheet runs a cell that starts with `=`, `+`, `-` or `@` (or a tab,
a carriage return, or the full-width forms of those signs) as a formula. Any such cell gets one
apostrophe in front, and so does any cell that already starts with an apostrophe. To read a value
exactly, remove one leading apostrophe if there is one.

**What is stable.** The columns, their order and the outcome words. A new column would go at the end.

### junit

JUnit XML, which most CI systems display. One `<testsuite>` holds one `<testcase>` per check, named
after the check, with `classname` `evidence-seal.` followed by the check's key. A check that passed has
no child. A check that failed has a `<failure type="FAIL">`, and a check that could not be done has a
`<failure type="NOT CHECKED">` whose message starts with `not checked:`, because NOT CHECKED is not a
pass. The detail is the failure message. `<properties>` carry the result, the manifest's name and
SHA-256, the token's name, when the check ran and the tool version, and `<system-out>` carries the
summary and the notes.

Characters XML 1.0 cannot hold, such as control characters, are written as visible escapes like
`\x1b`, so the file is always valid XML. The exit code still says the verdict, so a CI step can fail on
it directly.

```bash
python -m evidence_seal report examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt --format junit --out evidence-seal.junit.xml
```

**What is stable.** The element structure, the `type` values and the property names.

### pdf

A4 pages, using Helvetica, Helvetica-Bold and Courier, which every PDF reader has, so nothing is
embedded. Long lines wrap, the checks sit in a table, and every page shows its number. The same
check gives the same bytes: the PDF holds the time the check ran and nothing else that changes.

Those fonts hold the WinAnsi character set: Latin letters with their accents and common signs. Any
other character, such as Chinese or Cyrillic text in a file name, is written as a backslash code
like `\u4e2d`, its Unicode number, and the PDF then says so. The text and HTML reports show such
characters as they are.

A PDF looks official, and this one is not signed. It says on its last page that it proves nothing by
itself: the checks come from the manifest and the token, not from the PDF, and the commands in it
let anyone repeat them.

## export

```bash
python -m evidence_seal export examples/sealed/my-work-manifest.txt --out my-work.sha256
```

`export MANIFEST` writes the files a manifest lists with their SHA-256 hashes. It reads the manifest
and nothing else: no file is hashed and no token is opened, so it works on a manifest alone, and the
list proves nothing by itself. It says so on standard error.

| `--format` | Each line or record |
|---|---|
| `sha256sum` (default) | `HASH *path`, which `sha256sum -c` reads. |
| `bsd` | `SHA256 (path) = HASH`, which `shasum -c` and `sha256sum -c` read. |
| `csv` | Columns `path`, `size`, `sha256`, in the same CSV form as the report. |
| `json` | `{"export_schema": 1, "manifest": {...}, "sizes_recorded": ..., "files": [{"path", "size", "sha256"}]}` |

To check the files with `sha256sum` instead of this tool, run it inside the sealed folder:

```bash
sha256sum -c ../my-work.sha256
```

The star before each path asks for binary mode, so no system reads a file as text and changes its
bytes. A name holding a backslash, a line feed or a carriage return is written the way GNU
`sha256sum` writes one: the line starts with a backslash, and the name has `\\`, `\n` and `\r` in
place of those characters, and standard error says how many names were written that way. GNU
`sha256sum -c` reads them. uutils coreutils 0.8, the `sha256sum` on Ubuntu 26.04, skips such lines with
only a warning and still exits 0, so read its output for every file's `OK`; on Ubuntu,
`gnusha256sum -c` is the GNU one. A name that is not valid UTF-8 is written as its original bytes. A name
holding a lone surrogate, which only Windows allows, cannot be named in a checksum list at all; use
`--format json` or `csv` for such a manifest.

A hand-made manifest works too. If it does not record sizes, the size column is empty and `null` in
JSON, `sizes_recorded` is false, and standard error says so. A manifest whose entries use a hash other
than SHA-256, such as MD5, is refused with the reason, and nothing is written. So is a manifest that
lists no readable entry. A manifest that is internally inconsistent is exported as listed, with a
warning. Links and special files have no hash, so they are not exported, and standard error says how many.

Output goes to standard output unless `--out FILE` is given. Without `--force` no file is replaced,
and even with it an export never replaces the manifest or any of its companion files.

Exit codes: 0 written, 1 nothing written (the manifest cannot be listed this way), 2 bad arguments or
an unreadable file.

**What is stable.** The four layouts, the CSV columns, and the JSON fields under `export_schema` 1,
with the same promise as the JSON report.

## diff

```bash
python -m evidence_seal diff examples/sealed/my-work-manifest.txt examples/my-work
```

`diff OLD NEW` compares two file lists by name, size and SHA-256 hash. OLD is a manifest. NEW is a
manifest, or a folder, which is then hashed now, offline. It reports each file as one of:

| Outcome | Meaning |
|---|---|
| `unchanged` | The same name and the same hash. |
| `changed` | The same name and a different hash or size. |
| `added` | A name only NEW has, whose bytes are not those of a name only OLD has. |
| `removed` | A name only OLD has, whose bytes are not under any name only NEW has. |
| `moved` | A name only OLD has, whose exact bytes NEW has under a name only NEW has. |

It compares lists only. **It checks no token and proves no date,** and every output says so. To
check a proof, use `verify`.

A folder is walked exactly as `seal` walks it: links are not followed, and a file that cannot be read
stops the comparison. The exclude patterns recorded in OLD apply first, so anything the seal excluded stays
out, then `--exclude` and `--exclude-from` in the order given, with the same patterns as `seal`. OLD
and its companion files are skipped when they sit inside the folder. Your patterns also leave matching
paths out of both lists, so `--exclude` means "ignore these" whether NEW is a folder or a manifest.

A name that differs only in its Unicode form, as copying between macOS and other systems can cause, is
matched as `verify` matches it, and a note says how many matched that way. The hashes are still
compared. Links and special files are not compared, and a note gives their counts. When several files
share the same bytes, each one moves to at most one new name, in path order.

| `--format` | Output |
|---|---|
| `text` (default) | Counts, then each changed, added, removed and moved path. |
| `json` | `diff_schema` (now 1), `identical`, `old` and `new` (`name`, `kind`, `file_count`), `counts`, `changes` (each with `outcome`, `path`, `new_path`, `old_sha256`, `new_sha256`, `old_size`, `new_size`), `matched_under_another_unicode_form`, `notes` and `about`. |
| `csv` | Columns `path`, `outcome`, `new_path`, `old_sha256`, `new_sha256`, `old_size`, `new_size`, one row per file, unchanged ones included, in the same CSV form as the report. |
| `markdown` | Counts in a table and a list for each outcome, with names shown as in the Markdown report. |

`--out FILE` writes to a file instead of standard output. Without `--force` no file is replaced, and a
comparison never replaces either manifest or any of their companion files.

Exit codes: 0 the lists are identical, 1 they differ, 2 bad arguments or a file that cannot be read.
A manifest that cannot be compared, such as one that uses MD5, is an error and exits 2, so 1 always
means a real difference.

**What is stable.** The outcome words, the CSV columns, and the JSON fields under `diff_schema` 1, with
the same promise as the JSON report.
