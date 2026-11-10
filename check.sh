#!/bin/sh
# One-command check: unit tests, then an offline run of the real commands.
set -e
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1 && python3 -c "" >/dev/null 2>&1; then
    PY=python3
else
    PY=python
fi
"$PY" -m unittest discover

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# The commands below record into a library of their own, never the one in your home folder.
EVIDENCE_SEAL_HOME="$TMP/home"
export EVIDENCE_SEAL_HOME
FIXTURES=tests/fixtures
SAMPLE="$FIXTURES/local-authority/token-rsa.tsr"
ROOT="$FIXTURES/local-authority/root-rsa.crt"

"$PY" -m evidence_seal show "$SAMPLE" >/dev/null
"$PY" -m evidence_seal verify "$FIXTURES/sample-manifest.txt" --token "$SAMPLE" --folder "$FIXTURES/sample-folder" --ca "$ROOT" >/dev/null
"$PY" -m evidence_seal report "$FIXTURES/sample-manifest.txt" --token "$SAMPLE" --folder "$FIXTURES/sample-folder" --ca "$ROOT" --out "$TMP/report.txt" >/dev/null
grep -q "RESULT: VERIFIED" "$TMP/report.txt"
grep -q "openssl ts -verify" "$TMP/report.txt"

mkdir "$TMP/work"
printf 'first\n' >"$TMP/work/a.txt"
"$PY" -m evidence_seal seal "$TMP/work" --purpose "check.sh run" --out "$TMP/m.txt" >/dev/null

"$PY" -m evidence_seal verify examples/sealed/my-work-manifest.txt --folder examples/my-work --ca examples/sealed/test-authority-root.crt >/dev/null

# The library recorded those runs, is sound, and verifies the sample from its own copies.
"$PY" -m evidence_seal library check >/dev/null
"$PY" -m evidence_seal library list --json >"$TMP/library.json"
grep -q '"last_result": "VERIFIED"' "$TMP/library.json"
"$PY" -m evidence_seal library verify 5ea307 --ca "$ROOT" >/dev/null

# Each of these must not pass.
if "$PY" -m evidence_seal verify "$TMP/m.txt" >/dev/null; then
    echo "check.sh: a manifest with no token passed" >&2
    exit 1
fi
if "$PY" -m evidence_seal verify "$FIXTURES/sample-manifest.txt" --token "$SAMPLE" --folder "$TMP/work" --ca "$ROOT" >/dev/null; then
    echo "check.sh: a different folder passed" >&2
    exit 1
fi
if "$PY" -m evidence_seal verify "$TMP/m.txt" --token "$SAMPLE" --skip-files --ca "$ROOT" >/dev/null; then
    echo "check.sh: a token for another manifest passed" >&2
    exit 1
fi
echo "check.sh: all checks passed"
