# evidence-seal

Prove that exact files existed by a given date.

`evidence-seal` writes a text manifest of a folder's SHA-256 (Secure Hash Algorithm, 256 bit)
hashes, gets the manifest timestamped by a public authority under RFC 3161 (Request for Comments
3161, the internet timestamp standard), and later checks the whole thing and tells you exactly what
held up and what did not. A typical use is sealing your own work before signing an NDA
(non-disclosure agreement), so that months later you can show a skeptical third party what you
already had.

The manifest and token are ordinary files in standard formats, so anyone can check them with
`openssl` and never run this tool.

## Install

You need Python 3.9 or newer, and nothing else. There are no third-party packages. Check with
`python --version`. On Linux and macOS the command is often `python3`, so use that wherever this page
says `python`.

From a copy of this repository you can run it with no install at all. Run every command below from the
top of the repository:

```bash
python -m evidence_seal --version
```

To have an `evidence-seal` command that works from any folder, install it into a virtual environment.
`pip` fetches `setuptools` to build the package, so this one step needs the network:

```bash
python -m venv .venv
```

On Windows:

```bash
.venv\Scripts\python -m pip install .
```

```bash
.venv\Scripts\evidence-seal --version
```

On Linux and macOS:

```bash
.venv/bin/python -m pip install .
```

```bash
.venv/bin/evidence-seal --version
```

Installed, `evidence-seal seal ...` means the same as `python -m evidence_seal seal ...`.

## Quick start

These commands use the sample folder in `examples/my-work`, so you can run them exactly as written.
Then do the same with your own folder. [examples/README.md](examples/README.md) shows more, including
what a failure looks like, with no network.

**1. Seal a folder.** This stays offline. Pick a purpose you would be comfortable showing someone,
because it is part of what gets timestamped. Leave `--out` off with your own folder, and the manifest
goes beside the folder, named for it and today's date.

```bash
python -m evidence_seal seal examples/my-work --purpose "My designs before the Acme meeting" --out examples/my-work-manifest.txt
```

The manifest is plain text. Its hashes will be the same as these, because the folder is the same:

```text
evidence-seal manifest v1
purpose: My designs before the Acme meeting
created: 2026-11-07T17:00:00Z
folder: my-work
algorithm: sha256
files: 4
total-bytes: 490

40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880  256  data/readings.bin
5bd6628db6669ef12ab0fc4b6592c3087f3429f8c16e0422a8011d52ae2845fb  85  meeting-notes.txt
eae3b2b0cf87661da983053fd6335271b706582c3cdc297b19b829b1dba5b8f1  114  plans.txt
e665b2ff78469c4fcbfc52de87e880e1a7b2f101ecdf0ad697b2e21f6c0eff08  35  résumé draft.txt
```

**2. Get a timestamp.** This is the only command that uses the network, and it sends only a hash of
the manifest, not the manifest or any file. The sample purpose and hashes do no harm, but a token
cannot be taken back, so look before you stamp your own.

```bash
python -m evidence_seal stamp examples/my-work-manifest.txt
```

Beside the manifest you now have `.tsr` (the token), `.tsq` (the request) and `.ca.crt` (a copy of
the root certificate from the token). Keep them with the manifest. Keep the folder unchanged too, or
at least keep a copy: the seal proves a match, it cannot rebuild a file.

**3. Check it,** any time and on any computer. This stays offline.

```bash
python -m evidence_seal verify examples/my-work-manifest.txt
```

The checks look like this, and the last line tells you the result. The real output also has a section
at the top about the manifest, then what the token says and what no run can check. The manifest's hash
and the time will differ, because the `created` line and the moment of stamping differ. Two long values
are shortened here with `...`.

```text
FILES
  [PASS] Files match the manifest: 4 of 4 listed files unchanged, 0 changed, 0 missing, 0 added

TIMESTAMP TOKEN
  [PASS] Authority granted the timestamp: granted
  [PASS] Token is well formed: response, signed data and TSTInfo all parsed
  [PASS] Token covers this manifest: SHA-256 of the manifest is 5ea307f2..., the same as in the token
  [PASS] Token answers the saved request: hash and nonce match the saved request
  [PASS] Signature is valid: the signature verifies under the certificate of www.freetsa.org
      checked with: pure Python ECDSA P-384 with SHA-512
  [PASS] Certificate chain reaches a trusted root: chain www.freetsa.org -> www.freetsa.org, trusted through built-in fingerprint for the FreeTSA root
      checked with: pure Python RSA 4096 bit PKCS#1 v1.5 with SHA-512
  [PASS] Authority name matches the signer: O=Free TSA, ...
  [PASS] Token time is plausible: 2026-11-07 17:19:34 UTC is not in the future

RESULT: VERIFIED
```

**4. Give a reviewer one page.**

```bash
python -m evidence_seal report examples/my-work-manifest.txt --format html
```

## Why not just `sha256sum` and `openssl`

You can do this by hand, and the formats here are deliberately the same ones. The tool earns its
place in the parts that are easy to get wrong:

- **Hand-checks give one answer to several questions.** `openssl ts -verify` says nothing about
  whether your files still match. `verify` reports the files and the token as separate results, and
  names each changed, missing and added file.
- **"Could not check" never reads as a pass.** Every check is PASS, FAIL or NOT CHECKED. The overall
  result is VERIFIED only when every check passed, and the exit code says so.
- **A failed timestamp is never saved as a good one.** `stamp` checks the authority's answer before
  it writes anything. An HTML (HyperText Markup Language) error page, a rejection, an answer for
  other data and a bad signature all leave nothing on disk.
- **The manifest is byte-for-byte reproducible.** Sorted order, no line-ending conversion, and paths
  with awkward characters are escaped. A line removed from a manifest is noticed even with no token.
- **A reviewer gets a page they can read.** `report` writes one page saying what was checked, what it
  does and does not show, and the exact `openssl` commands to repeat the check.
- **It also reads what you already have.** Manifests and tokens made by hand work too.

## What the proof does and does not show

A VERIFIED result shows that the exact bytes of the manifest existed by the time in the token,
according to the authority that signed it, and that each file listed still has the bytes the
manifest records.

It does **not** show:

- **Who wrote the files.** A timestamp shows the data existed by that time, not who wrote it or who
  owned it. Anyone holding the same files could have made the same seal.
- **That the files are new.** They may be older than the token. The token sets a latest date, not an
  earliest one.
- **That the purpose or created fields are true.** They are statements by whoever made the manifest.
  The token only fixes that those words were there by that time.
- **Anything about files outside the manifest,** including excluded files. Each `exclude:` line is
  in the manifest and every verify run points it out, so a reader can see what was left out.
- **Anything but file contents.** File dates, permissions, owners and empty folders are not recorded.
- **That a certificate was not revoked.** This tool works offline and does not ask. Each run lists
  this as not checked.

The proof depends on the authority's continued credibility: that its clock was right and its signing
key was not misused. The public default is a free, best-effort service. It also depends on SHA-256
and the signature algorithm staying strong.

This is a technical tool and not legal advice. No claim is made that a seal is admissible or
persuasive in any proceeding. Ask a lawyer about that.

## Reading the results

| Result | Exit code | Meaning |
|---|---|---|
| VERIFIED | 0 | Every check passed. |
| FAILED | 1 | Something is wrong: a file changed, the token does not cover the manifest, a signature is bad, the authority refused. |
| (no verdict) | 2 | Bad arguments or a file that cannot be read. |
| INCOMPLETE | 3 | Nothing failed, but something could not be established: no token, no folder, an unknown root. **This is not a pass.** |
| (a bug) | 4 | Something went wrong inside this tool. No verdict was reached. Setting `EVIDENCE_SEAL_DEBUG=1` shows the details. |
| (interrupted) | 130 | You pressed Ctrl-C. No verdict was reached. |

`seal`, `stamp` and `show` use 0 for success, 1 for failure and 2 for usage errors, with 4 and 130
as above. Exit code 1 from `seal` or `stamp` means nothing was saved.

The two questions stay apart. `Files match the manifest` is about your files.
`Token covers this manifest` and `Signature is valid` are about the token. Any of them can pass while
another fails, and each has its own line. With `--json` the same results come as JSON (JavaScript
Object Notation).

Weak algorithms are not passes. A token, a chain or a manifest line that relies on MD5 (Message
Digest 5) or SHA-1, or an RSA (Rivest, Shamir, Adleman) key under 2048 bits, comes back as NOT CHECKED
with the reason, even when the arithmetic works out.

## Commands

Add `--help` after any command for its options.

**`seal FOLDER --purpose TEXT`** hashes raw bytes and never normalizes line endings, because that
would break the proof. `--exclude` and `--exclude-from` can repeat, and the patterns work like this:

- With no slash, a pattern matches a name at any depth: `--exclude .git`, `--exclude "*.tmp"`.
- With a slash, it matches from the top of the folder: `--exclude build/out`, `--exclude /top-only.txt`.
- `*` and `?` stop at a slash, and `**` stands for any number of folders: `--exclude "src/**/*.log"`.
- A trailing slash limits a pattern to folders: `--exclude cache/`.
- A leading `!` puts back what an earlier pattern left out: `--exclude build --exclude "!build/manual.txt"`.
  A name that really starts with `!` is written `/!name` or `**/!name`.

A pattern on a folder applies to everything inside it, and when several apply the last one wins, so
order matters. The patterns are recorded in the manifest in that order, and `verify` applies them
the same way. `--exclude-from FILE` reads one pattern per line, with blank lines and `#` comments
ignored, at its place in the order. Matching is case sensitive on every system. Seal warns about a
pattern that matched nothing, since it is often a typing mistake.
[examples/excludes.txt](examples/excludes.txt) is a list to start from.

A timestamp cannot be taken back, so look before you stamp. `--dry-run` opens no file and writes
nothing. It lists what would be sealed with sizes, and what would be left out by which pattern from
which file and line, and exits non-zero if a real run would fail. It needs no `--purpose`.

```bash
python -m evidence_seal seal examples/my-work --dry-run --exclude .git --exclude-from examples/excludes.txt
```

Links are listed by name and never followed. Their targets are not covered, and the output says so.
Every file is opened before hashing starts, so a locked or unreadable file stops the seal right away
and is named, and a seal can never quietly miss one. A file that changes while it is being read also
stops the seal. `--out` chooses the manifest path, and if that is inside the folder the manifest and
its token leave themselves out. `--date` sets the created field, which is only a claim.

Without `--force` no existing file is replaced. `--force` replaces a manifest, unless a token sits
beside it: replacing that manifest would make the token worthless, so choose a new name or move both.

The same folder, purpose and date always give identical bytes. A terminal shows a progress count
while long runs work. Pipes and files stay clean.

**`stamp MANIFEST`** defaults to `https://freetsa.org/tsr`, and `--tsa-url` picks another authority.
Terms for the default are at <https://freetsa.org/freetsa.html>. They ask for at most one request per
second per address and offer the service on a best-effort basis. `--hash` chooses `sha256`, `sha384`
or `sha512`. The request carries a random nonce, and the answer must repeat it.

A network failure, HTTP 429 (too many requests) or a 5xx error from the authority gets `--retries`
more attempts, 2 by default, with a wait between them that honors what the authority asks for up to
two minutes. `--timeout` limits each attempt, 60 seconds by default. Redirects are refused and named
in the message, because a redirected POST can silently turn into something else. With `--force`, a dated
copy of the token being replaced is kept, because an old token proves an earlier date and cannot be
issued again.

**`verify MANIFEST`** finds the `.tsr` beside the manifest, or use `--token`. A native manifest finds
its folder by the name it records, beside the manifest or as the folder holding it. A hand-made one
uses the folder holding the manifest. `--folder` overrides both. If the manifest is inside the folder
being checked, exactly its own companions (`.tsr`, `.tst`, `.tsq`, `.ca.crt`, the file of every report
format, and copies kept by `--force`) and the files named in the command are not compared, and
the output lists them.

- `--allow-added`: new files alone do not fail the file check. They are still listed.
- `--exclude PATTERN`, `--exclude-from FILE`: do not report new files matching this. Files in the manifest
  are always checked.
- `--skip-files`: check the token only. The result can then be at best INCOMPLETE.
- `--ca FILE`: trust this root certificate instead of the built-in fingerprints.
- `--untrusted FILE`: extra certificates to build the chain from, for tokens that do not carry them.
- `--query FILE`: compare against a saved request. A `.tsq` beside the token is used automatically.
- `--openssl`: also run `openssl ts -verify` and report its answer as one more check.

**`show TOKEN`** prints what a token says in plain language, checks nothing, and says so.

**`report MANIFEST`** runs the same checks as `verify` with the same options and exit codes, and
writes one page of text, or with `--format` HTML, JSON, Markdown, CSV, JUnit XML or PDF.
`--out -` prints it instead. [docs/REPORTS.md](docs/REPORTS.md) describes each format.

## Moving a seal to another computer

Copy the folder, the manifest and at least the `.tsr`. A manifest made on Windows has the same bytes as
one made on Linux from the same folder, so a token from either checks out on the other. What to watch:

- **Copy the bytes exactly.** Anything that converts line endings changes the files, and `verify` will
  say which. Git does this by default on some systems, and `.gitattributes` with `* -text` stops it.
  Zip, tar and plain copies leave the bytes alone.
- **Never convert the manifest.** A manifest with changed line endings fails both the file check and the
  token check, which is correct.
- **Unicode forms are forgiven and reported.** macOS and Linux can store `é` as one character or as two.
  `verify` matches either form, still compares the contents, and adds a note saying how many matched this way.
- **Case changes are not forgiven.** `Report.TXT` and `report.txt` are different names to the manifest.
  `verify` fails, and says where the same bytes are now.
- **Windows cannot hold every Linux name.** Names with `:`, `?` or `\` come through most copies changed,
  and `a.txt` and `A.txt` collapse into one file. `verify` fails and lists them, with the new name of each
  file it can find. Seal on the system where the files will be checked, or rename them first.

## When something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `cannot read ...: Permission denied` from `seal` | A file is locked or unreadable, and no manifest was written. | Close the program holding it, fix its permissions, or leave it out with `--exclude`. |
| `... changed while it was being read` | Something is writing to that file. | Stop that program, or leave the file out, and seal again. |
| `cannot write in ...` | The place beside the folder is read-only. Nothing was hashed yet. | Choose another place with `--out`. |
| `... covers the manifest ... would make the token worthless` | `--force` would orphan a token. | Choose a new name with `--out`, or move both files. |
| `could not reach ...` | The network or the authority is down. Nothing was saved. | Your manifest is safe. Run `stamp` again later. |
| `limiting requests (HTTP 429)` | The authority wants fewer requests. Nothing was saved. | Wait, and run `stamp` again. |
| `could not verify the secure connection` | This computer's date or root certificates are off. Nothing was saved. | Correct the date. An `http://` address also works, since the token is checked on its own merits. |
| `the authority's answer was not saved` | The answer failed a check, and the reason follows. | Try again. If it repeats, the authority is at fault, or use `--tsa-url`. |
| `[NOT CHECKED] Files match ...: the folder ... was not found` | The folder is not beside the manifest under the name it records. | Pass it with `--folder`. |
| `[NOT CHECKED] Certificate chain ...` | Nothing outside the token vouches for its root. | Get the authority's root yourself and pass it with `--ca`. |
| `uses format v2` | A newer tool wrote this manifest. Nothing is wrong with it. | Use a newer version of this tool. |
| `Token covers this manifest` fails | See the end of "Pairs made by hand". | |

If you interrupt a run, or the power fails, nothing is left half written. Files are written under a
temporary name and renamed once complete. A hard crash can leave a `.tmp` file beside the target, which
is safe to delete.

## Who is trusted

A token carries its own certificates, so a forger can include a whole fake chain. The chain therefore
proves nothing until it reaches a root chosen from outside the token. There are exactly two ways to
do that:

1. **`--ca FILE`:** you name the root. Built-in fingerprints are then turned off for that run.
2. **Built-in fingerprints:** `evidence_seal/trust.py` lists the SHA-256 fingerprint of the FreeTSA
   root, `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc`.

Otherwise the chain check is NOT CHECKED and the overall result is INCOMPLETE, however good the
signature is. The `.ca.crt` copy from `stamp` is only a convenience, and using it with `--ca` proves
nothing new. A reviewer should fetch the root from the authority and compare fingerprints.

Certificates are checked at the time in the token, not today, so a token stays checkable after its
certificate expires. Plain `openssl ts -verify` checks at today's date by default, so it starts
failing at that point unless given `-attime`. The report prints that form as well.

## Checking without this tool

`report` prints these with your own file names. A reviewer needs only `openssl`:

```bash
openssl x509 -in authority-root.crt -noout -fingerprint -sha256
```

```bash
openssl ts -verify -data my-work-manifest.txt -in my-work-manifest.tsr -CAfile authority-root.crt
```

```bash
openssl ts -reply -in my-work-manifest.tsr -text
```

```bash
openssl dgst -sha256 plans.txt
```

The manifest is plain text, so the last command's answer can be compared with its line by eye.
[docs/FORMAT.md](docs/FORMAT.md) describes every file in full.

## Pairs made by hand

Point `verify` at a manifest you made with `sha256sum` and `openssl`. Timestamps can be requested
with `openssl ts -query` and `curl`, and verified afterwards the same way.

```bash
python -m evidence_seal verify EVIDENCE.txt --token EVIDENCE.tsr --ca tsa-cacert.crt --untrusted tsa.crt --allow-added
```

Lines can be any of these, in any order, with either kind of line ending, in UTF-8, Latin-1 or UTF-16:

- `sha256sum` output: `HASH  path` and `HASH *path`, with SHA-1, SHA-256, SHA-384 or SHA-512 by length
- BSD tag and `openssl dgst` output: `SHA256 (path) = HASH`, `SHA2-256(path)= HASH`
- Extra date and size columns: `HASH  2026-03-04T12:00:00Z  1234  path`

Other lines count as free text. The token covers them as written, and the output says how many there
are. A line that starts like a hash but cannot be read leaves the file check at NOT CHECKED. A hand
list usually covers only part of a folder, which is what `--allow-added` is for.

The hash in a token covers the manifest's exact bytes. If a manifest was edited after stamping, even
just its line endings, then `verify` and `openssl ts -verify` will both fail, and that is correct.

A hash mismatch means the token does not cover these exact bytes. That is not by itself proof of
tampering: a hand-made manifest may have hashed a different form of the text, for example other line
endings or without a footer.

## How the checks work

| Check | What it does | With |
|---|---|---|
| Parsing | A hand-written DER (Distinguished Encoding Rules, the binary encoding of these tokens) parser reads ASN.1 (Abstract Syntax Notation One) structures for the request, the response, TSTInfo (the signed timestamp fields), and CMS (Cryptographic Message Syntax) signed data. Anything signed must be strict DER. | pure Python |
| Token hash | Hashes the manifest's bytes and compares with the token. | `hashlib` |
| Signature | RSA PKCS#1 v1.5 (Public-Key Cryptography Standards), RSA-PSS (Probabilistic Signature Scheme), and ECDSA (Elliptic Curve Digital Signature Algorithm) on P-256, P-384 and P-521. The signed attributes must match the content, and the signing-certificate attribute must name the certificate used. | pure Python |
| Chain | Validity at the token's time, basic constraints, key usage, and an extended key usage of exactly timeStamping, marked critical, with a signature checked at each link. | pure Python |
| Other curves | Brainpool and anything else pure Python here does not cover go to `openssl cms -verify` and `openssl verify`. Without `openssl`, the check is NOT CHECKED. | `openssl` when present |

Each result line says which path was used. Pure Python verification is fine for public data like
this, since there are no secrets for a timing attack to find. `openssl` is found on the path, or set
`EVIDENCE_SEAL_OPENSSL` to its location.

## What has been tested

Everything here was run on 2026-11-07 on one Windows computer: Windows 11 Pro on NTFS, and Ubuntu 26.04
on ext4 under WSL 2 (Windows Subsystem for Linux). Nobody else has run these numbers yet.

**The test suite.** 416 tests pass on Windows with Python 3.9.25, 3.11, 3.12.10 and 3.14, and on Linux
with Python 3.9.25 and 3.14.4 as a normal user. Nine skip on Windows, each because it needs something
Windows lacks here: POSIX (Portable Operating System Interface) signals and file modes, names Windows
cannot hold, or permission to create links. Those nine run on Linux, including both link tests. Three
skip on Linux, because they test Windows paths, and those run on Windows.

**Seals moving between systems.** A folder of 13 awkward files (both Unicode forms of a name, CRLF, LF
and CR line endings, `aux.txt`, a path over 260 characters, several non-Latin scripts) was tried both ways:

| Tried | Result |
|---|---|
| Sealed and stamped on Windows, checked on Linux | VERIFIED, and `openssl ts -verify` agreed |
| Sealed and stamped on Linux, checked on Windows | VERIFIED, and `openssl ts -verify` agreed |
| Same folder, purpose and date sealed on each | Identical bytes |
| A name changed from one Unicode form to the other | VERIFIED, with a note |
| A name changed only in case | FAILED, saying where the same bytes are now |
| A file's line endings converted | FAILED, naming the file |
| Names Windows cannot hold, copied to NTFS | FAILED, 5 missing and 4 added, with new names as hints |

**Real authorities.** `https://freetsa.org/tsr` and `http://freetsa.org/tsr` issued tokens that came back
VERIFIED. `http://timestamp.digicert.com` issued one with a good signature and an INCOMPLETE result, as
designed, because no built-in fingerprint or `--ca` vouches for its root.

**Real failures.**

| Condition | What happened |
|---|---|
| Host name that does not resolve, and an address that never answers, over `http` and `https` | Plain message, exit 1, nothing saved |
| File held open with no sharing, Windows | `seal` exit 1 and no manifest. `verify` INCOMPLETE, with the file under `unreadable` |
| Read-only manifest with `--force`, Windows | Exit 1, the manifest unchanged |
| Full disk on Linux, new manifest | Exit 1, plain message, no file left behind |
| Full disk on Linux, `--force` over a good manifest | Exit 1, the old manifest unchanged byte for byte |
| Interrupt signal during a 1.5 GB seal, Linux | Exit 130, no manifest and no temporary file |

**Size.** One run each, on a computer doing other work at the time, so read these as rough sizes, not
benchmarks. The 100,000 files are small and the manifest for them is 8,792,860 bytes.

| Job | Linux, ext4 | Windows, NTFS |
|---|---|---|
| `seal`, 100,000 files | 9.1 s | 729.8 s |
| `seal --dry-run`, 100,000 files | 1.1 s | 4.6 s |
| `verify`, 100,000 files | 2.0 s | 70.6 s |
| `verify` after 3 changes, all 3 named correctly | 1.9 s | 67.7 s |
| `seal`, one 5 GiB file | 16.2 s | 5.3 s |
| `verify`, one 5 GiB file | 3.0 s | 5.4 s |

Memory peaked at 137 MB for the 100,000 files and 25 MB for the 5 GiB file, measured on Linux. The Windows
`seal` figure is mostly the first read of new files. In a separate run with 10,000 files, the first `seal`
took 64.8 s, the next two took 6.6 s and 6.5 s, and `verify` took 5.6 s and 5.8 s. A profile of the
repeat run put the time in reading files. The cause of the slow first read was not established.

## What has not been tested

- **macOS has never run this,** including APFS (Apple File System) and the way macOS stores names. The
  Unicode-form checks ran on Windows and Linux, with both forms created on purpose.
- **A real outage or rate limit from a public authority was never seen.** HTTP 429, 503, HTML pages, garbage,
  empty and cut-off answers, stalls, redirects and oversized answers were all served by a local test server.
- **Ctrl-C on Windows.** Linux got a real signal. On Windows only a simulated interrupt was tried.
- **Network shares, FAT and exFAT, and proxies.**
- **Hosted CI.** [docs/CI.md](docs/CI.md) is a starting point that has never run on a hosted service.
- **A real expired certificate.** Validity at the token's time is covered by unit tests with made-up dates.
- **Long-term checks.** Every real token here is less than a day old.
- **Outside review.** No independent security audit or legal review has been done.

## Layout

| Path | Job |
|---|---|
| `evidence_seal/cli.py` | Arguments, exit codes and plain error messages |
| `evidence_seal/sealing.py`, `scan.py`, `manifest.py` | The seal command, safe file writing, walking and hashing, and manifest formats |
| `evidence_seal/stamping.py` | The stamp command, and the only network code |
| `evidence_seal/verification.py`, `tokencheck.py`, `results.py` | The verify flow, each token check, and verdicts |
| `evidence_seal/showing.py`, `render.py`, `reporting.py`, `text.py` | Text, HTML and JSON output, the `openssl` commands, and safe display |
| `evidence_seal/report_formats.py`, `pdf.py` | The table of report formats, the formats beyond text and HTML, and a small PDF writer |
| `evidence_seal/exporting.py`, `comparing.py` | The export and diff commands |
| `evidence_seal/der.py`, `tsp.py`, `cms.py`, `x509.py` | Binary formats |
| `evidence_seal/rsa.py`, `ecdsa.py`, `signatures.py`, `hashes.py`, `oids.py` | Cryptographic checks and names |
| `evidence_seal/chain.py`, `trust.py`, `openssl_bridge.py` | Certificate paths, trusted roots, and calling `openssl` |
| `examples/` | A sample folder, a finished seal of it, and worked examples |
| `docs/` | File formats, report formats, and a CI (continuous integration) setup to copy |

## Tests

```bash
python -m unittest discover
```

```bash
sh check.sh
```

No test leaves your computer. The stamp tests talk to small servers on the loopback address. Tests that
compare against `openssl` skip with a clear message when it is missing, and the rest still run.
`tests/fixtures/README.md` says where every fixture came from. The local test authorities are test-only
and their private keys were discarded. [CONTRIBUTING.md](CONTRIBUTING.md) has the rules for changes, and
[SECURITY.md](SECURITY.md) says how to report a problem and what the tool defends against.

## License

MIT. See [LICENSE](LICENSE).
