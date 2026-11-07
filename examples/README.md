# Worked examples

Run these from the top of the repository. On Linux and macOS you may need `python3` where these say
`python`. All of them work offline.

`my-work/` is a small folder of made-up files, with both kinds of line ending, a binary file and a name
with an accent. `sealed/` holds a finished seal of it: a manifest, a token, and the root certificate of
the authority that signed it.

**That authority is a test.** Its name says TEST ONLY, and its key comes from a fixed seed in
`tests/forge.py`, so anyone can make tokens with it. This token proves nothing about any date. It exists
so you can see every result without using the network.

## 1. A seal that checks out

```bash
python -m evidence_seal verify examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt
```

Ends with `RESULT: VERIFIED` and exit code 0. Every check passed, and each has its own line.

## 2. The same seal without naming a root

```bash
python -m evidence_seal verify examples/sealed/my-work-manifest.txt --folder examples/my-work
```

Ends with `RESULT: INCOMPLETE` and exit code 3. The signature is fine, but a token can carry any chain
it likes, and nothing outside the token vouches for this root. This is not a pass.

## 3. A changed file

Open `examples/my-work/plans.txt`, add a line and save it. Then run the command from example 1 again.
It ends with `RESULT: FAILED` and exit code 1, and `Changed (1)` names `plans.txt`. The token checks
still pass, because the manifest was not touched, and the two results stay apart.

Put the file back before going on:

```bash
git checkout -- examples/my-work/plans.txt
```

## 4. A new file

Create any new file in `examples/my-work`, and run the command from example 1. It fails, with the file
under `Added (1)`. With `--allow-added` new files alone do not fail the check, and they are still listed.

```bash
python -m evidence_seal verify examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt --allow-added
```

Delete the new file when you finish.

## 5. Looking before sealing

`--dry-run` opens and writes nothing. `excludes.txt` is a sample list of patterns to start from, with
the junk files operating systems tend to add. Copy it and edit it for your own folder.

```bash
python -m evidence_seal seal examples/my-work --dry-run --exclude-from examples/excludes.txt
```

## 6. Reading a token

This prints what the token says, checks nothing, and says so.

```bash
python -m evidence_seal show examples/sealed/my-work-manifest.tsr
```

## 7. A page for a reviewer

`--out -` prints the page. Use a file name to keep it, and `--format html` for a page to open or print.
It includes the `openssl` commands that repeat the check without this tool.

```bash
python -m evidence_seal report examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt --out -
```

## 8. A real timestamp

The README's quick start seals the same folder and gets a real token from a public authority.
