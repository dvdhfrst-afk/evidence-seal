# Using it in CI

These are snippets to copy. This repository ships no workflow files of its own, and the snippets have
not been run on any hosted CI (continuous integration) service. The commands inside them have been run
by hand.

## Testing this tool

The matrix shows the two systems the tests are meant to run on. Each system runs tests the other skips.

```yaml
name: tests
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        python: ["3.9", "3.14"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - run: python -m unittest discover
```

## Checking a sealed folder on a schedule

This fails the job if a sealed folder stops matching. It works offline, so it needs no secrets. The
exit code is 0 only for VERIFIED, and INCOMPLETE fails the job too, which is usually what you want.

```bash
python -m evidence_seal verify seals/my-work-manifest.txt --folder my-work --json
```

To keep a reviewer's page as a build artifact:

```bash
python -m evidence_seal report seals/my-work-manifest.txt --folder my-work --format html --out seal-report.html --force
```

## Sealing a release

Keep `stamp` out of any job that runs often. The default authority asks for at most one request per
second per address and is a best-effort service, so stamp a release and not every commit. If the
checkout's line endings can differ from the release's, seal the built files and not the working tree.

```bash
python -m evidence_seal seal release-files --purpose "Release 2.3.0 as built" --out release-files-manifest.txt
```

```bash
python -m evidence_seal stamp release-files-manifest.txt --retries 3 --timeout 30
```

`stamp` exits 0 only when it saved a token that passed its checks, and exit 1 means nothing was saved.
