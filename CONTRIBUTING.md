# Contributing

## Running the tests

You need Python 3.9 or newer, and nothing else. `openssl` is optional: tests that compare against it
skip with a message when it is missing.

```bash
python -m unittest discover
```

```bash
sh check.sh
```

No test leaves your computer. The stamp tests talk to small servers on the loopback address.
A few tests only run on Windows or only on Linux and macOS, because they exercise names or permissions
the other system does not have. A change to how files are walked or named should be run on both.

## Rules the tests enforce

`tests/test_repo_rules.py` holds these, so a mistake shows up as a failure and not in review:

- Standard library only, and syntax that Python 3.9 can read.
- Python sources are plain ASCII, and every text file uses line feeds.
- Network code lives only in `stamping.py`, which asks authorities for tokens, `local_server.py`,
  the loopback-only local test authority, and `web/server.py`, the loopback-only web interface.
  Other programs start only from `openssl_bridge.py`.
- No private keys and no email addresses in any file, including inside certificates in fixtures.
- Every command in the documents parses, and no document chains commands on one line.

## Rules worth knowing

- **Never convert line endings or normalize bytes.** `.gitattributes` turns conversion off, because a
  changed byte breaks the tokens in the fixtures and the sample folder.
- **A check has three outcomes.** PASS, FAIL or NOT CHECKED. If something could not be established,
  it must never read as a pass, and a missing tool is not a failure.
- **Text from outside goes through `text.printable` before it is shown.** That covers anything from a
  file, a file name, a token or a certificate.
- **The manifest format is a promise.** [docs/FORMAT.md](docs/FORMAT.md) says what may change. New
  header lines or a new entry form need a new format version, and old manifests must keep working.
  `tests/fixtures/portable/golden-manifest.txt` must never be regenerated to make a test pass.
- **Nothing here may claim more than a timestamp shows.** Keep the README's section on what the proof
  does and does not show true, and make no claims about legal effect.
- **Numbers in the README come from real runs.** If you change one, say how you measured it.

## Fixtures

`tests/fixtures/README.md` says where each one came from. All of it is synthetic. `tests/forge.py`
builds tokens that are validly signed but wrong in one specific way, from keys made from fixed seeds,
so its tokens prove nothing to anyone.

## Changes

Keep each change small enough to read, add a test that fails without it, and add a line to
[CHANGELOG.md](CHANGELOG.md) when a user would notice. For a CI (continuous integration) setup you can
copy, see [docs/CI.md](docs/CI.md).
