"""X.509 certificates: enough parsing to validate a timestamp authority's chain."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from . import der, oids
from .errors import CertificateFileError, DerError, TokenFormatError
from .signatures import AlgorithmId, parse_public_key

KU_DIGITAL_SIGNATURE = 0
KU_NON_REPUDIATION = 1
KU_KEY_CERT_SIGN = 5

_PEM_BLOCK = re.compile(
    rb"-----BEGIN (?:TRUSTED |X509 )?CERTIFICATE-----(.+?)-----END (?:TRUSTED |X509 )?CERTIFICATE-----",
    re.DOTALL,
)


class Name:
    """A distinguished name with its exact bytes and a readable form."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.rdns: List[List[Tuple[str, str]]] = []
        node = der.parse(raw)
        if not node.is_universal(der.SEQUENCE):
            raise DerError("a name must be a sequence")
        for rdn in node.children:
            if not rdn.is_universal(der.SET):
                raise DerError("a name component must be a set")
            parts: List[Tuple[str, str]] = []
            for pair in rdn.children:
                if not pair.is_universal(der.SEQUENCE):
                    raise DerError("a name attribute must be a sequence")
                cursor = der.Cursor(pair, "name attribute")
                oid = der.oid_value(cursor.universal(der.OID, "type"))
                value = cursor.next("value")
                cursor.finish()
                try:
                    parts.append((oid, der.text_value(value)))
                except DerError:
                    parts.append((oid, "#" + value.raw.hex()))
            self.rdns.append(parts)

    def display(self) -> str:
        rendered = []
        for rdn in self.rdns:
            for oid, text in rdn:
                rendered.append(f"{oids.NAME_ATTRIBUTES.get(oid, oid)}={text}")
        return ", ".join(rendered) if rendered else "(empty name)"

    def common_name(self) -> Optional[str]:
        for rdn in self.rdns:
            for oid, text in rdn:
                if oid == "2.5.4.3":
                    return text
        return None

    def _normal(self):
        return tuple(
            tuple(sorted((oid, " ".join(text.split()).casefold()) for oid, text in rdn)) for rdn in self.rdns
        )

    def matches(self, other: "Name") -> bool:
        """Name comparison in the RFC 5280 style: same bytes, or same after case and space folding."""
        return self.raw == other.raw or self._normal() == other._normal()


@dataclass(frozen=True)
class Extension:
    oid: str
    critical: bool
    value: bytes


class Certificate:
    """One parsed certificate. Parsing is strict: a certificate must be real DER."""

    def __init__(self, raw: bytes):
        self.raw = bytes(raw)
        outer = der.Cursor(der.parse(self.raw), "certificate")
        tbs_node = outer.universal(der.SEQUENCE, "signed body")
        self.tbs_raw = tbs_node.raw
        self.signature_algorithm = AlgorithmId.parse(outer.universal(der.SEQUENCE, "signature algorithm"))
        self.signature = der.bit_octets(outer.universal(der.BIT_STRING, "signature"))
        outer.finish()

        tbs = der.Cursor(tbs_node, "certificate body")
        version_node = tbs.optional_context(0)
        self.version = 1
        if version_node is not None:
            if len(version_node.children) != 1:
                raise DerError("bad certificate version")
            self.version = der.int_value(version_node.children[0]) + 1
        self.serial = der.int_value(tbs.universal(der.INTEGER, "serial number"))
        inner_algorithm = AlgorithmId.parse(tbs.universal(der.SEQUENCE, "signature algorithm"))
        if inner_algorithm != self.signature_algorithm:
            raise TokenFormatError("certificate states two different signature algorithms")
        self.issuer = Name(tbs.universal(der.SEQUENCE, "issuer").raw)
        validity = der.Cursor(tbs.universal(der.SEQUENCE, "validity"), "validity")
        self.not_before: datetime = der.time_value(validity.next("start"))
        self.not_after: datetime = der.time_value(validity.next("end"))
        validity.finish()
        self.subject = Name(tbs.universal(der.SEQUENCE, "subject").raw)
        self.spki_raw = tbs.universal(der.SEQUENCE, "public key").raw
        self.public_key = parse_public_key(self.spki_raw)
        tbs.optional_context(1)
        tbs.optional_context(2)
        self.extensions: Dict[str, Extension] = {}
        extensions_node = tbs.optional_context(3)
        tbs.finish()
        if extensions_node is not None:
            self._read_extensions(extensions_node)

    def _read_extensions(self, wrapper: der.Node) -> None:
        if len(wrapper.children) != 1 or not wrapper.children[0].is_universal(der.SEQUENCE):
            raise DerError("bad certificate extensions")
        for item in wrapper.children[0].children:
            cursor = der.Cursor(item, "certificate extension")
            oid = der.oid_value(cursor.universal(der.OID, "identifier"))
            critical = False
            flag = cursor.optional_universal(der.BOOLEAN)
            if flag is not None:
                critical = der.bool_value(flag)
            value = der.octets(cursor.universal(der.OCTET_STRING, "value"))
            cursor.finish()
            if oid in self.extensions:
                raise TokenFormatError(f"certificate repeats extension {oid}")
            self.extensions[oid] = Extension(oid, critical, value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Certificate) and self.raw == other.raw

    def __hash__(self) -> int:
        return hash(self.raw)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    @property
    def self_issued(self) -> bool:
        return self.subject.matches(self.issuer)

    def basic_constraints(self) -> Tuple[bool, Optional[int]]:
        """Whether this is a certificate authority, and its path length limit."""
        extension = self.extensions.get(oids.EXT_BASIC_CONSTRAINTS)
        if extension is None:
            return False, None
        cursor = der.Cursor(der.parse(extension.value), "basic constraints")
        flag = cursor.optional_universal(der.BOOLEAN)
        is_ca = der.bool_value(flag) if flag is not None else False
        length = cursor.optional_universal(der.INTEGER)
        cursor.finish()
        return is_ca, der.int_value(length) if length is not None else None

    def key_usage(self) -> Optional[Set[int]]:
        extension = self.extensions.get(oids.EXT_KEY_USAGE)
        if extension is None:
            return None
        return der.bit_flags(der.parse(extension.value))

    def extended_key_usage(self) -> Optional[List[str]]:
        extension = self.extensions.get(oids.EXT_EXTENDED_KEY_USAGE)
        if extension is None:
            return None
        node = der.parse(extension.value)
        if not node.is_universal(der.SEQUENCE):
            raise DerError("bad extended key usage")
        return [der.oid_value(child) for child in node.children]

    def subject_key_id(self) -> Optional[bytes]:
        extension = self.extensions.get(oids.EXT_SUBJECT_KEY_ID)
        if extension is None:
            return None
        return der.octets(der.parse(extension.value))

    def to_pem(self) -> str:
        body = base64.b64encode(self.raw).decode("ascii")
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def certificates_from_bytes(data: bytes, label: str) -> List[Certificate]:
    """Reads one DER certificate, or every certificate in a PEM file."""
    found: List[Certificate] = []
    blocks = _PEM_BLOCK.findall(data)
    try:
        if blocks:
            for block in blocks:
                try:
                    decoded = base64.b64decode(b"".join(block.split()), validate=True)
                except ValueError:
                    raise CertificateFileError(f"{label}: bad base64 in a PEM block") from None
                found.append(Certificate(decoded))
        elif data[:1] == b"\x30":
            found.append(Certificate(data))
    except (DerError, TokenFormatError) as exc:
        raise CertificateFileError(f"{label}: not a valid certificate: {exc}") from None
    if not found:
        raise CertificateFileError(f"{label}: no certificates found")
    return found


def load_certificates(path: Path) -> List[Certificate]:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise CertificateFileError(f"cannot read {path}: {exc.strerror or exc}") from None
    return certificates_from_bytes(data, str(path))
