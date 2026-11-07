"""Regenerates the test-only local authority fixtures. Needs openssl.

Every private key is created in a temporary folder and deleted when this script
ends. Only certificates and tokens are kept, so nobody can issue more tokens
from these test authorities. All subject names say TEST ONLY.

Run from the repository root:

    python tests/fixtures/make_fixtures.py

The tests never run this. They use the committed output and need no openssl.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from evidence_seal import sealing  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE / "local-authority"
FOLDER = HERE / "sample-folder"
MANIFEST = HERE / "sample-manifest.txt"
HANDMADE = HERE / "handmade-manifest.txt"
OPENSSL = shutil.which("openssl")
DAYS = "36500"


def run(*arguments):
    done = subprocess.run([OPENSSL] + [str(item) for item in arguments], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"openssl {' '.join(str(a) for a in arguments)}\n{done.stdout}\n{done.stderr}")
    return done.stdout


def make_key(path, kind):
    if kind == "rsa":
        run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path)
    else:
        run("genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{kind}", "-out", path)


def make_root(work, name, kind):
    key = work / f"{name}.key"
    make_key(key, kind)
    cert = OUT / f"{name}.crt"
    run(
        "req", "-new", "-x509", "-key", key, "-out", cert, "-days", DAYS, "-sha256",
        "-subj", f"/O=evidence-seal tests/OU=TEST ONLY/CN=TEST ONLY {name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    return key, cert


def make_tsa(work, name, kind, root_key, root_cert, sign_options=()):
    key = work / f"{name}.key"
    make_key(key, kind)
    request = work / f"{name}.csr"
    run("req", "-new", "-key", key, "-out", request, "-subj", f"/O=evidence-seal tests/OU=TEST ONLY/CN=TEST ONLY {name}")
    extensions = work / f"{name}.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=critical,timeStamping\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n"
    )
    cert = OUT / f"{name}.crt"
    run(
        "x509", "-req", "-in", request, "-CA", root_cert, "-CAkey", root_key, "-CAcreateserial",
        "-CAserial", work / f"{name}.srl", "-out", cert, "-days", DAYS, "-sha256",
        "-extfile", extensions, *sign_options,
    )
    return key, cert


def write_config(work, name, key, cert, chain, digest="sha256"):
    config = work / f"{name}.cnf"
    serial = work / f"{name}.serial"
    serial.write_text("01\n")
    config.write_text(
        "[tsa]\n"
        f"default_tsa = {name}\n"
        f"[{name}]\n"
        f"serial = {serial.as_posix()}\n"
        "crypto_device = builtin\n"
        f"signer_cert = {cert.as_posix()}\n"
        f"certs = {chain.as_posix()}\n"
        f"signer_key = {key.as_posix()}\n"
        f"signer_digest = {digest}\n"
        "default_policy = 1.2.3.4.1\n"
        "digests = sha1, sha256, sha384, sha512\n"
        "accuracy = secs:1, millisecs:500, microsecs:100\n"
        "ordering = yes\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n"
        "ess_cert_id_alg = sha256\n"
    )
    return config


def make_token(work, config, data, name, cert_req=True, hash_option="-sha256", bare=False):
    query = work / f"{name}.tsq"
    arguments = ["ts", "-query", "-data", data, hash_option, "-out", query]
    if cert_req:
        arguments.insert(-2, "-cert")
    else:
        arguments.insert(-2, "-no_nonce")
    run(*arguments)
    suffix = ".tst" if bare else ".tsr"
    token = OUT / f"{name}{suffix}"
    reply = ["ts", "-reply", "-config", config, "-queryfile", query, "-out", token]
    if bare:
        reply.append("-token_out")
    run(*reply)
    shutil.copyfile(query, OUT / f"{name}.tsq")
    return token


def write_sample_folder():
    (FOLDER / "data").mkdir(parents=True, exist_ok=True)
    (FOLDER / "notes.txt").write_bytes(b"Plain synthetic notes.\nA second line.\n")
    (FOLDER / "windows-endings.txt").write_bytes(b"This file keeps CRLF line endings.\r\nOn purpose.\r\n")
    (FOLDER / "data" / "blob.bin").write_bytes(bytes(range(256)))
    (FOLDER / "data" / "name with spaces.txt").write_bytes(b"A file whose name has spaces.\n")


def write_manifests():
    if MANIFEST.exists():
        MANIFEST.unlink()
    sealing.seal_folder(FOLDER, "Synthetic test folder for the evidence-seal test suite", out=MANIFEST, created="2026-01-15")
    from evidence_seal import hashes, scan

    lines = ["Hand-made evidence manifest (synthetic, for tests)", "", "Tool: sha256sum, then edited by hand", ""]
    walked = scan.walk(FOLDER, scan.Excludes())
    for relative, digest, size in scan.hash_all(walked.files, hashes.SHA256):
        lines.append(f"{digest}  2026-01-15T00:00:00Z  {size:>8}  {relative}")
    HANDMADE.write_bytes(("\r\n".join(lines) + "\r\n").encode("utf-8"))


def main():
    if OPENSSL is None:
        raise SystemExit("openssl is required to regenerate the fixtures")
    OUT.mkdir(exist_ok=True)
    for old in OUT.iterdir():
        old.unlink()
    write_sample_folder()
    write_manifests()
    with tempfile.TemporaryDirectory(prefix="evidence-seal-fixtures-") as temp:
        work = Path(temp)
        root_rsa_key, root_rsa = make_root(work, "root-rsa", "rsa")
        root_ec_key, root_ec = make_root(work, "root-ec", "P-256")
        make_root(work, "other-root", "P-256")
        pool_key, pool_cert = make_root(work, "root-brainpool", "brainpoolP256r1")

        tsa_rsa_key, tsa_rsa = make_tsa(work, "tsa-rsa", "rsa", root_rsa_key, root_rsa)
        tsa_ec_key, tsa_ec = make_tsa(work, "tsa-ec", "P-384", root_ec_key, root_ec)
        tsa_pss_key, tsa_pss = make_tsa(
            work, "tsa-pss", "rsa", root_rsa_key, root_rsa,
            ("-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"),
        )
        tsa_pool_key, tsa_pool = make_tsa(work, "tsa-brainpool", "brainpoolP256r1", pool_key, pool_cert)

        rsa_config = write_config(work, "rsa", tsa_rsa_key, tsa_rsa, root_rsa)
        ec_config = write_config(work, "ec", tsa_ec_key, tsa_ec, root_ec, digest="sha384")
        pss_config = write_config(work, "pss", tsa_pss_key, tsa_pss, root_rsa)
        pool_config = write_config(work, "pool", tsa_pool_key, tsa_pool, pool_cert)

        make_token(work, rsa_config, MANIFEST, "token-rsa")
        make_token(work, ec_config, MANIFEST, "token-ec")
        make_token(work, pss_config, MANIFEST, "token-pss-chain")
        make_token(work, pool_config, MANIFEST, "token-brainpool")
        make_token(work, rsa_config, MANIFEST, "token-nocerts", cert_req=False)
        make_token(work, rsa_config, MANIFEST, "token-bare", bare=True)
        make_token(work, rsa_config, MANIFEST, "token-sha1-imprint", hash_option="-sha1")
        make_token(work, rsa_config, MANIFEST, "token-sha512-imprint", hash_option="-sha512")
        make_token(work, ec_config, HANDMADE, "token-handmade")
    print(f"wrote {len(list(OUT.iterdir()))} files to {OUT}")


if __name__ == "__main__":
    main()
