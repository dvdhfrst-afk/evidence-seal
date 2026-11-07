# evidence-seal

Prove that exact files existed by a given date.

`evidence-seal` writes a text manifest of a folder's SHA-256 (Secure Hash Algorithm, 256 bit)
hashes, gets the manifest timestamped by a public authority under RFC 3161 (Request for Comments
3161, the internet timestamp standard), and later checks the whole thing and tells you exactly what
held up and what did not. A typical use is sealing your own work before signing an NDA
(non-disclosure agreement), so that months later you can show a skeptical third party what you
already had.

It needs Python 3.9 or newer and nothing else. There is no install step and no third-party package.
Everything runs from the repository root as `python -m evidence_seal`. The manifest and token are
ordinary files in standard formats, so anyone can check them with `openssl` and never run this tool.

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

## Quick start

Seal a folder. This stays offline. Pick a purpose you would be comfortable showing someone, because
it is part of what gets timestamped.

```bash
python -m evidence_seal seal ../my-work --purpose "My designs before the Acme meeting" --exclude .git
```

This writes `my-work-manifest-2026-03-02.txt` beside the folder, dated today:

```text
evidence-seal manifest v1
purpose: My designs before the Acme meeting
created: 2026-03-02T15:04:05Z
folder: my-work
algorithm: sha256
exclude: .git
files: 2
total-bytes: 373

40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880  256  data/blob.bin
1f049302d98c1c4a1dcac2bc95e86b75d52c05be57b33544f7d32e41e2235385  117  notes.txt
```

Get a timestamp. This is the only command that uses the network, and it sends only a hash of the
manifest, not the manifest or any file.

```bash
python -m evidence_seal stamp ../my-work-manifest-2026-03-02.txt
```

Beside the manifest you now have `.tsr` (the token), `.tsq` (the request) and `.ca.crt` (a copy of
the root certificate from the token). Keep them with the manifest. Keep the folder unchanged too, or
at least keep a copy: the seal proves a match, it cannot rebuild a file.

Months later, check it:

```bash
python -m evidence_seal verify ../my-work-manifest-2026-03-02.txt
```

```text
FILES
  [PASS] Files match the manifest: 2 of 2 listed files unchanged, 0 changed, 0 missing, 0 added

TIMESTAMP TOKEN
  [PASS] Authority granted the timestamp: granted
  [PASS] Token is well formed: response, signed data and TSTInfo all parsed
  [PASS] Token covers this manifest: SHA-256 of the manifest is 5ea307f2..., the same as in the token
  [PASS] Signature is valid: the signature verifies under the certificate of www.freetsa.org
      checked with: pure Python ECDSA P-384 with SHA-512
  [PASS] Certificate chain reaches a trusted root: chain www.freetsa.org -> www.freetsa.org, trusted through built-in fingerprint for the FreeTSA root
      checked with: pure Python RSA 4096 bit PKCS#1 v1.5 with SHA-512
  [PASS] Authority name matches the signer: O=Free TSA, ...
  [PASS] Token time is plausible: 2026-03-02 15:06:11 UTC is not in the future

RESULT: VERIFIED
```

Then give a reviewer one page:

```bash
python -m evidence_seal report ../my-work-manifest-2026-03-02.txt --format html
```

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
| INCOMPLETE | 3 | Nothing failed, but something could not be established: no token, no folder, an unknown root. **This is not a pass.** |
| (usage error) | 2 | Bad arguments or a file that cannot be read. No verdict was reached. |

`seal`, `stamp` and `show` use 0 for success, 1 for failure and 2 for usage errors.

The two questions stay apart. `Files match the manifest` is about your files.
`Token covers this manifest` and `Signature is valid` are about the token. Any of them can pass while
another fails, and each has its own line. With `--json` the same results come as JSON (JavaScript
Object Notation).

Weak algorithms are not passes. A token, a chain or a manifest line that relies on MD5 (Message
Digest 5) or SHA-1, or an RSA (Rivest, Shamir, Adleman) key under 2048 bits, comes back as NOT CHECKED
with the reason, even when the arithmetic works out.

## Commands

**`seal FOLDER --purpose TEXT`** hashes raw bytes and never normalizes line endings, because that
would break the proof. Excludes have two forms, and `--exclude` can repeat:

- With no slash, the pattern matches a name at any depth: `--exclude .git`, `--exclude "*.tmp"`.
- With a slash, it matches the whole relative path: `--exclude build/out`, `--exclude /top-only.txt`.

Links are listed by name and never followed. Their targets are not covered, and the output says so.
If a file cannot be read the seal stops, so a seal can never quietly miss one. `--out` chooses the
manifest path, and if that is inside the folder the manifest and its token leave themselves out.
`--date` sets the created field, which is only a claim. Without `--force` no existing file is replaced.

The same folder, purpose and date always give identical bytes.

**`stamp MANIFEST`** defaults to `https://freetsa.org/tsr`, and `--tsa-url` picks another authority.
Terms for the default are at <https://freetsa.org/freetsa.html>. They ask for at most one request per
second per address and offer the service on a best-effort basis. `--hash` chooses `sha256`, `sha384`
or `sha512`. The request carries a random nonce, and the answer must repeat it.

**`verify MANIFEST`** finds the `.tsr` beside the manifest, or use `--token`. A native manifest finds
its folder by the name it records, beside the manifest or as the folder holding it. A hand-made one
uses the folder holding the manifest. `--folder` overrides both. If the manifest is inside the folder
being checked, exactly its own companions (`.tsr`, `.tst`, `.tsq`, `.ca.crt`, `.report.txt`,
`.report.html`) and the files named in the command are not compared, and the output lists them.

- `--allow-added`: new files alone do not fail the file check. They are still listed.
- `--exclude PATTERN`: do not report new files matching this. Files in the manifest are always checked.
- `--skip-files`: check the token only. The result can then be at best INCOMPLETE.
- `--ca FILE`: trust this root certificate instead of the built-in fingerprints.
- `--untrusted FILE`: extra certificates to build the chain from, for tokens that do not carry them.
- `--query FILE`: compare against a saved request. A `.tsq` beside the manifest is used automatically.
- `--openssl`: also run `openssl ts -verify` and report its answer as one more check.

**`show TOKEN`** prints what a token says in plain language, checks nothing, and says so.

**`report MANIFEST`** runs the same checks as `verify` with the same options and exit codes, and
writes one page of text, or HTML with `--format html`. `--out -` prints it instead.

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
openssl ts -verify -data my-work-manifest-2026-03-02.txt -in my-work-manifest-2026-03-02.tsr -CAfile authority-root.crt
```

```bash
openssl ts -reply -in my-work-manifest-2026-03-02.tsr -text
```

```bash
openssl dgst -sha256 notes.txt
```

The manifest is plain text, so the last command's answer can be compared with its line by eye.

## Pairs made by hand

Point `verify` at a manifest you made with `sha256sum` and `openssl`. Timestamps can be requested
with `openssl ts -query` and `curl`, and verified afterwards the same way.

```bash
python -m evidence_seal verify EVIDENCE.txt --token EVIDENCE.tsr --ca tsa-cacert.pem --untrusted tsa.crt --allow-added
```

Lines can be any of these, in any order, with either kind of line ending:

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

## Layout

| Module | Job |
|---|---|
| `cli.py` | Arguments and exit codes |
| `sealing.py`, `scan.py`, `manifest.py` | The seal command, walking and hashing, and manifest formats |
| `stamping.py` | The stamp command, and the only network code |
| `verification.py`, `tokencheck.py`, `results.py` | The verify flow, each token check, and verdicts |
| `showing.py`, `render.py`, `reporting.py` | Text, HTML and JSON output, and the `openssl` commands |
| `der.py`, `tsp.py`, `cms.py`, `x509.py` | Binary formats |
| `rsa.py`, `ecdsa.py`, `signatures.py`, `hashes.py`, `oids.py` | Cryptographic checks and names |
| `chain.py`, `trust.py`, `openssl_bridge.py` | Certificate paths, trusted roots, and calling `openssl` |

## Tests

```bash
python -m unittest discover
```

```bash
sh check.sh
```

No test touches the network or opens a window. Tests that compare against `openssl` skip with a clear
message when it is missing, and the rest still run. `tests/fixtures/README.md` says where every
fixture came from. The local test authorities are test-only and their private keys were discarded.

## License

MIT. See [LICENSE](LICENSE).
