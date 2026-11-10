# Settings and profiles

If you run the same commands with the same options every week, put those options in a settings
file. A **profile** is a named set of them, chosen with `--profile NAME`. Nothing in the file is
needed: with no settings file, every command behaves exactly as it does without one.

Settings fill in options for `seal`, `stamp`, `verify` and `report`. They never change what a
manifest records beyond what the same options on the command line would: a manifest made with a
profile is format v1, byte for byte the same as one made by typing those options.

## Where the file is

`settings.ini` in this tool's own folder:

| System | Folder |
|---|---|
| Windows | `%APPDATA%\evidence-seal` |
| macOS | `~/Library/Application Support/evidence-seal` |
| Linux and others | `$XDG_DATA_HOME/evidence-seal`, or `~/.local/share/evidence-seal` |

The `EVIDENCE_SEAL_HOME` environment variable moves that folder. To see the path and whether the
file exists:

```bash
python -m evidence_seal config path
```

`--settings FILE` on any command uses another file instead, and `--no-settings` ignores the file.

## An example

```ini
# Settings for the lab. Comments and blank lines are kept when a command changes a value.

[settings]
version = 1

[defaults]
timeout = 30
exclude =
    .git
    *.tmp

[profile lab]
authority = https://tsa.example.test/tsr
ca =
    certs/lab-root.crt
purpose = Lab notebook {folder}, sealed {date}
report-format = html
```

With that file, `python -m evidence_seal seal week-45 --profile lab` seals with the purpose
`Lab notebook week-45, sealed 2026-11-09`, leaves out `.git` and `*.tmp`, and `stamp --profile lab`
asks `tsa.example.test` with a 30 second timeout.

## The file

- **Sections.** `[settings]` holds only `version = 1`. `[defaults]` applies to every run. Each
  `[profile NAME]` applies when chosen. Any other section is a mistake, and so is a section that
  appears twice.
- **Keys.** One per line, as `key = value`, under a section. Keys are lowercase and exactly as
  listed below, and a key may appear once in a section.
- **Lists.** `ca`, `untrusted`, `exclude` and `exclude-from` take several values: leave the key line
  empty and put one value on each following indented line. A single value may also go on the key
  line. A list written with no values at all, `exclude =`, means none, which lets a profile clear a
  list that `[defaults]` sets.
- **Comments.** A line whose first character other than spaces is `#` or `;`. Comments are whole
  lines only, because `#` can be part of a value such as a purpose. They may sit between the values
  of a list.
- **Paths.** A relative path in `ca`, `untrusted` or `exclude-from` is relative to the folder that
  holds the settings file, and `~` means your home folder. `config set` stores the full path.
- **Text.** UTF-8, with or without a byte order mark. UTF-16 with a byte order mark, which Windows
  PowerShell 5.1 writes when output is redirected to a file, is read too and written back the same
  way. Line endings are kept, whether LF or CRLF. Control characters, other than tabs, are refused.
  The file may be at most 1 MB.
- **Profile names.** Letters, digits, hyphens, underscores and dots, starting with a letter or a
  digit, at most 64 characters. Names are case sensitive.

## Every key

| Key | Value | Built-in default | Used by |
|---|---|---|---|
| `authority` | An `http://` or `https://` URL | `https://freetsa.org/tsr` | stamp, as `--tsa-url` |
| `timeout` | Seconds, more than 0 and less than a day | `60` | stamp |
| `retries` | A whole number from 0 to 10 | `2` | stamp |
| `hash` | A strong hash: `sha256`, `sha384` or `sha512` | `sha256` | stamp |
| `policy` | A policy object identifier such as `1.2.3.4` | none | stamp |
| `ca` | Root certificate files, a list | none | stamp, verify, report |
| `untrusted` | Extra certificate files, a list | none | verify, report |
| `exclude` | Exclude patterns, a list | none | seal, verify, report |
| `exclude-from` | Files of exclude patterns, a list | none | seal, verify, report |
| `allow-added` | `yes` or `no` | `no` | verify, report |
| `openssl` | `yes` or `no` | `no` | verify, report |
| `report-format` | One of the formats `report --format` takes: `text` or `html` | `text` | report |
| `purpose` | Text, which may use `{folder}` and `{date}` | none | seal, as `--purpose` |
| `library` | `on` or `off`: whether commands record what they do in the library | `on` | the library |

A key that a command does not use is ignored by that command, so one profile can serve them all.
`authority` takes a URL, or the name of an entry in the authority list (see
[AUTHORITIES.md](AUTHORITIES.md)). A name works like `stamp --authority NAME`: the entry's URL, hash,
policy and roots are used, `ca` from the settings is not, and `hash` or `policy` set in the settings
still win over the entry's. `stamp` and `config check` report a name that is not in the list.

In `purpose`, `{folder}` is the sealed folder's name and `{date}` is the date of the manifest's
created field, in UTC, such as `2026-11-09`. Write `{{` and `}}` for a brace itself. Any other name
in braces is refused.

## Which value wins

For each option, the first of these that gives a value is used:

1. the command line,
2. the profile chosen with `--profile`,
3. `[defaults]`,
4. the built-in default.

A profile key replaces the same key in `[defaults]`, lists included: a profile with its own `ca`
uses only its own roots. A few rules are worth knowing:

- **`--ca` and `--untrusted` replace the settings.** Giving either on the command line means the
  settings' list for that option is not used at all.
- **Exclude patterns add up, in order.** Patterns read from the `exclude-from` files come first, then
  the `exclude` patterns, then each `--exclude` and `--exclude-from` from the command line in the
  order given. The last pattern that applies wins, so a command-line `!pattern` can put back a file
  that a profile excludes:

  ```bash
  python -m evidence_seal seal week-45 --profile lab --exclude "!scratch.tmp" --dry-run
  ```

  The manifest records every pattern used, from the settings and the command line alike, so
  `verify` needs no profile to apply them again.
- **`purpose` applies only when `--purpose` is not given.** A purpose typed on the command line always wins.
- **The command line can turn `allow-added` and `openssl` on, but not off.** To run without them
  when the settings turn them on, choose a profile that sets them to `no`, or use `--no-settings`.
- **A profile that does not exist is an error**, and the message lists the profiles that do.

To see the value every key has and where it came from:

```bash
python -m evidence_seal config show --profile lab
```

## Commands

Each command takes `--settings FILE` to work on another file, and `--help` for its options.

| Command | What it does |
|---|---|
| `config path` | Prints where the settings file is and whether it exists. |
| `config show [--profile NAME] [--json]` | Prints the value in effect for every key and where it came from: built-in, or the section, file and line. |
| `config get KEY [--profile NAME]` | Prints the value in effect for one key, one line per item. |
| `config set KEY VALUE... [--profile NAME]` | Sets a value in `[defaults]`, or in a profile. Creates the file if needed. |
| `config unset KEY [--profile NAME]` | Removes a value, so the next place in line applies. |
| `config check` | Lists every problem with its file and line, including named files that are missing. Exit 0 when there are none, 1 when there are. |
| `profile list [--json]` | Lists the profiles. |
| `profile show NAME [--json]` | Prints what one profile sets itself. |
| `profile create NAME [--from OTHER]` | Adds a profile at the end of the file, empty or as a copy of another. |
| `profile copy OLD NEW` | The same as `profile create NEW --from OLD`. |
| `profile rename OLD NEW` | Renames a profile. Its lines and comments stay. |
| `profile delete NAME` | Removes a profile, with the comment lines just above it. |

```bash
python -m evidence_seal config set timeout 30
```

```bash
python -m evidence_seal profile create travel --from lab
```

```bash
python -m evidence_seal config set exclude .git "*.tmp" --profile lab
```

```bash
python -m evidence_seal config check
```

A change rewrites only the lines of the value being changed. Every other byte stays as it was:
comments, blank lines, order, line endings and a byte order mark. Comment lines between the old
values of a list stay too, after the new values. The new file is written under a temporary name and
renamed into place, so it is never left half written, and if something else changed the file while
the command ran, nothing is written. A value that would be refused in the file is refused by
`config set` too, with the same reason. `config set` cannot write an empty list; edit the file for
that.

## When the file has a problem

A file with any problem, such as an unknown key, a bad value or a line that cannot be read, is not
used at all, and `seal`, `stamp`, `verify` and `report` stop with exit code 2 before doing anything.
That is on purpose: a mistyped `exclude` that was quietly skipped would seal files you meant to leave
out. The message names the file and line of the first problem, and `config check` lists them all,
with a suggestion when a name looks like a typo:

```text
settings.ini line 9: there is no setting 'exlude' in [defaults]; did you mean 'exclude'?
```

To run anyway, add `--no-settings`. `config set` and `config unset` still work when the problem is
a wrong or misspelled value, so either can fix one, but they change nothing in a file whose lines
cannot all be read.

A file whose `[settings]` section says a version newer than 1 was written by a newer evidence-seal.
This version does not use it and never changes it, and says so. Use the newer version, or
`--no-settings`.
