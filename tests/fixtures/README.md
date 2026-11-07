# Test fixtures

All the data here is synthetic.

- `sample-folder/`: a small folder with text, CRLF and binary files.
- `sample-manifest.txt`: the native manifest of that folder.
- `handmade-manifest.txt`: a manifest in the style people make by hand, with CRLF
  line endings and free text.
- `local-authority/`: **test only.** Certificates and tokens from throwaway test
  authorities, whose names all say TEST ONLY. These prove nothing about anything.
  `make_fixtures.py` creates them with openssl and deletes every private key when
  it ends, so nobody can issue more tokens from them. Re-running it replaces the
  whole folder and needs no network.

- `portable/`: a manifest and token for a folder that `tests/test_portability.py` rebuilds from a
  table on whatever system runs the tests. The same bytes must come out everywhere. Never regenerate
  these to make a test pass, because they are what holds the format steady. The token comes from
  `tests/forge.py`.

`tests/forge.py` builds further tokens in memory, with fresh keys and pure Python,
so that the wrong-in-one-specific-way cases need neither key files nor openssl.

`.gitattributes` turns off every line-ending conversion, so git never changes the
bytes of these files. A changed byte would break the tokens that cover them.
