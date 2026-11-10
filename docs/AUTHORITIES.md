# Timestamp authorities

A timestamp is only as good as the authority that signed it, and a token only verifies when its
certificate chain reaches a root you chose yourself. This page covers the list of authorities this
tool knows, how to add a real one safely, and the local test authority for trying the tool offline.

## The authority list

```bash
python -m evidence_seal authority list
```

```bash
python -m evidence_seal authority show FreeTSA
```

There are two kinds of entry:

- **Built in.** FreeTSA, with the SHA-256 fingerprint of its root written into
  `evidence_seal/trust.py`. Built-in entries cannot be removed or changed. No copy of the root is
  stored, so `authority show` gives the address where the authority publishes it.
- **Yours.** Entries you add live in `authorities.json` in this tool's home folder, with a copy of
  every root you chose in the `authorities` folder beside it, named by its fingerprint. The home
  folder is `%APPDATA%\evidence-seal` on Windows, `~/Library/Application Support/evidence-seal` on
  macOS and `~/.local/share/evidence-seal` elsewhere. The `EVIDENCE_SEAL_HOME` environment variable
  moves it.

Each entry has a name, a URL, its roots, and optionally a policy OID (object identifier), a hash and a
note. `authority show NAME --json` and `authority list --json` print everything.

The file says `"format": 1`. A list written by a newer version of this tool is refused with a plain
message and never rewritten. A damaged list stops every command that needs it with a message naming
the file, and nothing in it is changed. Each stored root must still match the fingerprint recorded
for it, so swapping a root file by hand is reported as damage, not trusted.

## What the list changes

| Command | Trusted roots |
|---|---|
| `verify`, `report` | The built-in fingerprints and every root in your list. With `--ca`, only the files you name. |
| `stamp --authority NAME` | Only that entry's roots. An answer that chains anywhere else is not saved. |
| `stamp` with `--tsa-url` | As for `verify`, or only the `--ca` files when given. |

When the root that a chain reached belongs to an entry, the result names it, for example "trusted
through the root of example in your authority list".

Your list is yours alone. Someone checking your evidence on another computer does not have it, and
should get the authority's root from the authority and compare fingerprints, as `report` explains.

`stamp --authority NAME` takes the entry's URL, policy and hash. `--hash` and `--policy` on the
command line take precedence, and `--tsa-url` and `--ca` cannot be combined with it.

## Adding a real authority safely

Adding a root is a decision to trust it: every token that chains to it will verify on this computer.
So the root must come from the authority, and its fingerprint must be checked against a source you
trust that is separate from the file itself.

1. Get the authority's RFC 3161 URL and its root certificate from the authority's own website.
2. Print the certificate's fingerprint:

   ```bash
   openssl x509 -in tsa-root.crt -noout -fingerprint -sha256
   ```

3. Compare it with the fingerprint the authority publishes through another channel you trust: a
   page served over HTTPS, its policy document, or a colleague who already uses it. If they differ,
   stop.
4. Add it. The command prints the fingerprint again, so you can compare once more:

   ```bash
   python -m evidence_seal authority add example-tsa https://tsa.example.test/tsr --root tsa-root.crt --note "terms in the contract folder"
   ```

5. Stamp with it:

   ```bash
   python -m evidence_seal stamp my-work-manifest.txt --authority example-tsa
   ```

To change an entry, use `authority trust NAME --root FILE` to add a root (an authority may publish a
new one), `authority untrust NAME FINGERPRINT` to stop trusting one, and `authority remove NAME` to
drop the entry. Tokens from an authority you removed still verify with `--ca` and its root.
`authority root NAME --out FILE` writes the stored copies of its roots.

Names are up to 48 letters, digits, dots, hyphens and underscores, start with a letter or digit, and
are compared without regard to case. Roots must be self-signed certificate authority certificates.

## The local test authority

The local test authority runs on this computer and needs no network. It is for trying the tool and
for tests. **Its tokens prove nothing to anyone else.** Whoever holds its key file can sign any date
at all, and nobody but you trusts its root. Every certificate it makes says TEST ONLY, its key file
says so in its name and its contents, and `verify`, `report`, `show` and `stamp` all say plainly
when a token comes from it. The verdict itself is worked out exactly as for any other authority.

```bash
python -m evidence_seal test-authority init
```

This makes a folder named `test-authority` in the home folder (or the folder you give), holding:

- `root.crt`: a fresh EC P-256 root. Its key is used once, to sign the timestamping certificate,
  and is then thrown away, so no other signer can be made under it.
- `signer.crt`: the timestamping certificate, with a critical extended key usage of timeStamping.
- `TEST-ONLY-signer-key.pem`: the signer's private key. On Linux and macOS only you can read it. On
  Windows, in the home folder, it is protected by that folder's permissions, which belong to your
  account. Elsewhere, choose a folder only you can read.
- `authority.json`: its name, its creation date, and its policy OID, which is made from a random
  UUID (an OID under 2.25), so no two test authorities share one.

It also adds the root to your authority list as `local-test`, marked as a test authority. Options:

- `--name TEXT`: a name to put in its certificates.
- `--days N`: how long its certificates are valid, from 1 day. A short one shows what happens when
  a certificate expires after it signed a token: the token still verifies, with a note.
- `--force`: replace the test authority already in that folder, and its `local-test` entry. Tokens
  from the old one stop verifying on this computer.
- `--no-register`: leave the authority list alone. Then `verify` needs `--ca` with its `root.crt`.

```bash
python -m evidence_seal test-authority info
```

prints its root fingerprint, validity dates, policy and the URL to use.

### Serving it

```bash
python -m evidence_seal test-authority serve
```

It listens on `http://127.0.0.1:3161/tsr` until Ctrl+C. It answers POST requests of type
`application/timestamp-query`, and GET `/` with a short page. It binds to a loopback address only:
`--host` accepts `127.0.0.1`, another `127.x.x.x` address, `::1` or `localhost`, and refuses
anything else. `--port N` picks another port, and `--port 0` any free one. The URL it prints is the
one to use. When it differs from the listed `http://127.0.0.1:3161/tsr`, stamp with `--tsa-url`.

It honors the request's nonce, its request for certificates and its hash (SHA-256, SHA-384 or
SHA-512). It issues only under its own policy: a request for any other policy, a weak hash, a
request with extensions or bytes that are not a request are refused with the status and failure
code RFC 3161 gives for each. Requests over 64 KB are refused before they are read, and a client
that stops sending is dropped after 10 seconds.

### Switches for seeing how stamp handles trouble

| Switch | What the test authority does | What stamp does |
|---|---|---|
| `--refuse` | Answers every request with a rejection status | Saves nothing, and prints the reason given |
| `--busy N` | Answers the first N requests with HTTP 429 and `Retry-After: 1` | Waits and asks again, up to `--retries` times |
| `--delay SECONDS` | Waits before each answer | Gives up after `--timeout` seconds |
| `--time ISO` | Signs this time, such as `2026-03-01T12:00:00Z`, instead of now | Saves nothing for a time before its certificates were valid, or more than a day ahead |
| `--broken` | Answers bytes that are not a token | Saves nothing |

```bash
python -m evidence_seal test-authority serve --busy 2 --delay 1
```

### In tests

`evidence_seal.local_server.LocalServer` runs the same server inside a Python process, on a free
port: `LocalServer(local_authority.load(folder)).start()` returns it, `.url` is the address to stamp
with, and `.stop()` ends it. It also works in a `with` block.

## An offline walkthrough

Everything below runs on one computer, with no network. Make the test authority once:

```bash
python -m evidence_seal test-authority init
```

Start it, and leave that window open:

```bash
python -m evidence_seal test-authority serve
```

In a second window, seal a folder, stamp the manifest, and verify:

```bash
python -m evidence_seal seal my-work --purpose "Trying evidence-seal" --out my-work-manifest.txt
```

```bash
python -m evidence_seal stamp my-work-manifest.txt --authority local-test
```

```bash
python -m evidence_seal verify my-work-manifest.txt
```

The result is VERIFIED, because your own list trusts the test root, and the chain line names it:

```text
  [PASS] Certificate chain reaches a trusted root: chain TEST ONLY local timestamping 1f3a9c2e -> TEST ONLY local root 1f3a9c2e, trusted through the root of local-test in your authority list, a local test authority

RESULT: VERIFIED
...
This token comes from local-test, a local test authority on this computer. It proves nothing to anyone else: whoever holds its key file can sign any date.
```

On any other computer the same token is INCOMPLETE, because nothing there trusts its root. That is
the point: a test token shows how the tool works, never when your files existed. For real evidence,
stamp with a public authority such as FreeTSA, or one you added after checking its fingerprint.

When you are done, stop the server with Ctrl+C and remove the entry:

```bash
python -m evidence_seal authority remove local-test
```
