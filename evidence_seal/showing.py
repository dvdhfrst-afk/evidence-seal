"""The show command: what a token says, in plain language, without judging it."""

from __future__ import annotations

from typing import Any, Dict, List

from . import authorities, cms, tokencheck, tsp
from .text import printable_block
from .trust import authority_for_root
from .x509 import Certificate


def _certificate_facts(cert: Certificate) -> Dict[str, Any]:
    known = authority_for_root(cert.sha256)
    listed = authorities.entry_for_root(cert.sha256)
    return {
        "subject": cert.subject.display(),
        "issuer": cert.issuer.display(),
        "valid_from": cert.not_before.strftime("%Y-%m-%d"),
        "valid_to": cert.not_after.strftime("%Y-%m-%d"),
        "key": cert.public_key.describe(),
        "sha256": cert.sha256,
        "known_root": known.name if known else None,
        "listed_root": listed.name if listed is not None and not listed.builtin else None,
    }


def describe(token_bytes: bytes) -> Dict[str, Any]:
    """Facts from a token as plain data. Raises when the bytes are not a token at all."""
    response = tsp.parse_response(token_bytes)
    facts = tokencheck.facts_of(response)
    out: Dict[str, Any] = facts.to_dict()
    out["granted"] = response.granted
    out["failure"] = response.failure_text() or None
    out["certificates"] = []
    out["signer"] = None
    out["test_authority"] = None
    signed = response.signed_data
    if signed is not None:
        out["certificates"] = [_certificate_facts(cert) for cert in signed.certificates]
        out["test_authority"] = authorities.test_authority_for(signed.certificates)
        if len(signed.signers) == 1:
            signer = cms.find_signer_certificate(signed.signers[0], signed.certificates)
            if signer is not None:
                out["signer"] = signer.subject.display()
                out["signer_sha256"] = signer.sha256
    return out


def render_text(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    if data["time"] is None:
        lines.append(f"This is a timestamp response with no token. The authority's answer: {data['status']}.")
        if data["failure"]:
            lines.append(f"Reason given: {data['failure']}")
        lines.append("It proves nothing about any data.")
        return printable_block(lines)
    lines.append("This is an RFC 3161 timestamp token.")
    lines.append("")
    lines.append("What it claims:")
    lines.append(f"  The data with {data['hash_algorithm']} hash")
    lines.append(f"    {data['hash_hex']}")
    lines.append(f"  existed by {data['time']}.")
    lines.append("")
    lines.append("Details:")
    lines.append(f"  Authority's answer: {data['status']}")
    lines.append(f"  Authority named in token: {data['authority'] or 'not stated'}")
    lines.append(f"  Signed by certificate of: {data['signer'] or 'not in this file'}")
    lines.append(f"  Time: {data['accuracy']}")
    lines.append(f"  Policy: {data['policy']}")
    lines.append(f"  Serial number: {data['serial']}")
    lines.append(f"  Nonce: {data['nonce'] or 'none'}")
    lines.append(f"  Hash algorithm: {data['hash_algorithm']}")
    if data["failure"]:
        lines.append(f"  Reason given: {data['failure']}")
    lines.append("")
    lines.append(f"Certificates carried in the token: {len(data['certificates'])}")
    for cert in data["certificates"]:
        lines.append(f"  {cert['subject']}")
        lines.append(f"    issued by {cert['issuer']}")
        lines.append(f"    valid {cert['valid_from']} to {cert['valid_to']}, {cert['key']}")
        lines.append(f"    SHA-256 {cert['sha256']}")
        if cert["known_root"]:
            lines.append(f"    this fingerprint is built in as the {cert['known_root']} root")
        elif cert["listed_root"]:
            lines.append(f"    this is the root of {cert['listed_root']} in your authority list")
    lines.append("")
    if data["test_authority"]:
        lines.append(
            f"This token comes from {data['test_authority']}, a local test authority on this computer."
            " It proves nothing to anyone else."
        )
    lines.append("Nothing above has been verified. This command only reads the token. Use verify to check it.")
    return printable_block(lines)
