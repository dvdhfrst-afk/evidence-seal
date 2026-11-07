"""RSA signature verification in pure Python: PKCS#1 v1.5 and PSS.

Only public key operations are here. Nothing secret is handled, so the lack of
constant time arithmetic does not matter.
"""

from __future__ import annotations

from .hashes import HashAlgorithm


def _recover(n: int, e: int, signature: bytes) -> bytes:
    size = (n.bit_length() + 7) // 8
    if len(signature) != size:
        raise ValueError("signature length does not match the key size")
    value = int.from_bytes(signature, "big")
    if value >= n:
        raise ValueError("signature is out of range")
    return pow(value, e, n).to_bytes(size, "big")


def verify_pkcs1_v15(n: int, e: int, algorithm: HashAlgorithm, digest: bytes, signature: bytes) -> bool:
    """Rebuilds the one valid padded block and compares it whole.

    Comparing the whole block, instead of parsing the recovered padding, is what
    rules out the forgeries that lax padding parsers have allowed.
    """
    try:
        recovered = _recover(n, e, signature)
    except ValueError:
        return False
    info = algorithm.digest_info(digest)
    padding = len(recovered) - len(info) - 3
    if padding < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + info
    return recovered == expected


def _mgf1(seed: bytes, length: int, algorithm: HashAlgorithm) -> bytes:
    output = b""
    counter = 0
    while len(output) < length:
        output += algorithm.digest(seed + counter.to_bytes(4, "big"))
        counter += 1
    return output[:length]


def verify_pss(
    n: int,
    e: int,
    algorithm: HashAlgorithm,
    mgf_algorithm: HashAlgorithm,
    salt_length: int,
    digest: bytes,
    signature: bytes,
) -> bool:
    """EMSA-PSS verification from RFC 8017 section 9.1.2."""
    try:
        recovered = _recover(n, e, signature)
    except ValueError:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    if len(recovered) > em_len:
        if recovered[0] != 0:
            return False
        recovered = recovered[1:]
    if em_len < algorithm.size + salt_length + 2 or recovered[-1] != 0xBC:
        return False
    db_len = em_len - algorithm.size - 1
    masked = recovered[:db_len]
    tag = recovered[db_len:-1]
    top_mask = 0xFF >> (8 * em_len - em_bits)
    if masked[0] & ~top_mask & 0xFF:
        return False
    mask = _mgf1(tag, db_len, mgf_algorithm)
    block = bytearray(a ^ b for a, b in zip(masked, mask))
    block[0] &= top_mask
    padding = db_len - salt_length - 1
    if any(block[:padding]) or block[padding] != 0x01:
        return False
    salt = bytes(block[padding + 1:])
    return algorithm.digest(b"\x00" * 8 + digest + salt) == tag
