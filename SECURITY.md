# Security

## Reporting a problem

Please do not put the details of a security problem in a public issue. Use the private vulnerability
reporting of whatever site hosts this repository. If it has none, open an issue that says only that
you have something to report privately, and ask for a private channel.

A useful report gives the version (`python -m evidence_seal --version`), the command, and the smallest
files that show the problem. Never send files you are not allowed to share.

## What this tool does on your computer

- `seal`, `verify`, `show` and `report` use no network at all.
- `stamp` makes one outgoing HTTP or HTTPS request per attempt, to the authority you name or the
  default. The request holds the hash of the manifest, a random nonce and a request for certificates.
  It holds no file names, no file contents and no text from the manifest.
- Only `test-authority serve` listens on a port, and only on a loopback address (`127.0.0.1` unless
  you choose another loopback address). Any other address is refused, so nothing on the network can
  reach it. It runs until you stop it. Nothing else listens, and there is no telemetry.
- `stamp` honors the usual `http_proxy` and `https_proxy` settings, through Python's standard library.
- `openssl` runs only with `verify --openssl`, or for a curve or extension that pure Python here does
  not cover. It gets files through a private temporary folder. `EVIDENCE_SEAL_OPENSSL` chooses the
  program, so treat that setting as you would your `PATH`.

## What is treated as hostile

A manifest, a token, a certificate, a folder and the authority's answer can all come from someone who
wants to mislead you. So can the authority list in the home folder, and any request that reaches the
local test authority. These are the defenses, each with tests in `tests/test_hostile_input.py`,
`tests/test_stamp_network.py`, `tests/test_authority_list.py` and `tests/test_local_authority.py`:

| Attack | Defense |
|---|---|
| A manifest lists `../../secret` or an absolute path | Entries are looked up among the files walked inside the folder. A manifest path is never opened directly. |
| A manifest names a folder such as `..` or `C:` | Only a plain name beside the manifest is accepted. |
| A file name or purpose holds a line feed, to fake `RESULT: VERIFIED` | Everything shown goes through one function, a line at a time, that writes control characters as escapes. |
| Terminal escape codes, or characters that reverse how a line displays | The same function. JSON output is plain ASCII. |
| HTML in a purpose or a file name | The HTML report escapes every value. |
| A file name a shell would act on, in a report's `openssl` commands | The report tells the reader to copy that file to a plain name first, and uses the plain name. |
| A link pointing at a good copy of a changed file | Links and special files are listed by name and never followed or opened. |
| A token carrying its own fake chain | A chain counts only if it reaches a root you named with `--ca`, a fingerprint built in, or a root you added to your authority list. |
| A damaged or hand-edited authority list | It is size limited, every field is checked, and each stored root must match the fingerprint recorded for it. Any problem stops the command with a message naming the file. A newer format is refused and never rewritten. |
| A token from the local test authority presented as evidence | `verify`, `report` and `show` say plainly that it comes from a local test authority and proves nothing to anyone else. Its certificates and key file say TEST ONLY. |
| Hostile requests to the local test authority | Bodies over 64 KB are refused unread, slow clients are dropped after 10 seconds, and request bytes are parsed strictly and refused as RFC 3161 says. |
| A token signed with a weak hash or a short key | NOT CHECKED, even when the arithmetic works. |
| Bytes built to break a parser: nesting, wrong lengths, truncation | The DER (Distinguished Encoding Rules) parser limits depth and checks every length. Damage ends in a verdict or a plain error, tested with random damage. |
| A huge RSA key, or hundreds of certificates with one name, to tie up the tool | Key size is capped at 16384 bits, and a chain search at 64 signature checks. |
| An authority that redirects, stalls or sends too much | Redirects are refused, each attempt has an overall time limit, and answers over 4 MB are refused. |
| A wrong answer from an authority | The hash, nonce, signature, chain, name and time are all checked before anything is saved. |

## What this does not defend against

- **A compromised computer.** If something can change this tool or your files while you run it, no
  result it prints can be trusted. `openssl` gives a second opinion from separate code; see "Checking
  without this tool" in the README.
- **A compromised or dishonest authority.** The proof rests on its clock and key. Revocation is not checked.
- **Someone who can write to this tool's home folder.** They could add a root to your authority list,
  just as they could replace this tool. Use `--ca` when you need to rule that out.
- **Weakness found later in SHA-256 or in a signature algorithm.** A token cannot be strengthened after
  the fact by this version of the tool.

This code has had no independent security audit. The signature checks are pure Python and handle only
public data, so timing attacks have nothing to find, but they are also newer and less reviewed than
`openssl`. Use `verify --openssl` when the stakes justify a second opinion.
