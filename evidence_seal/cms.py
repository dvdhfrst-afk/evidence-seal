"""Cryptographic Message Syntax: the SignedData envelope around a timestamp."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import der, hashes, oids
from .errors import TokenFormatError
from .signatures import AlgorithmId
from .x509 import Certificate, Name


@dataclass
class EssCertId:
    """One entry of a signing-certificate attribute: a hash of the signer's certificate."""

    hash_oid: str
    digest: bytes


@dataclass
class SignerInfo:
    version: int
    issuer: Optional[Name]
    serial: Optional[int]
    subject_key_id: Optional[bytes]
    digest_algorithm: AlgorithmId
    signed_attrs_raw: Optional[bytes]
    attributes: Dict[str, List[der.Node]]
    signature_algorithm: AlgorithmId
    signature: bytes

    def signed_message(self) -> bytes:
        """What the signature covers: the attributes, re-tagged as a SET per RFC 5652."""
        if self.signed_attrs_raw is None:
            raise TokenFormatError("the signer has no signed attributes")
        return b"\x31" + self.signed_attrs_raw[1:]

    def single_attribute(self, oid: str) -> Optional[der.Node]:
        values = self.attributes.get(oid)
        if values is None:
            return None
        if len(values) != 1:
            raise TokenFormatError(f"signed attribute {oid} must have exactly one value")
        return values[0]

    def matches_certificate(self, cert: Certificate) -> bool:
        if self.issuer is not None:
            return self.serial == cert.serial and self.issuer.matches(cert.issuer)
        return self.subject_key_id is not None and self.subject_key_id == cert.subject_key_id()

    def signing_cert_ids(self) -> Optional[List[EssCertId]]:
        """The signing-certificate attribute, in either version. None when it is absent."""
        found: List[EssCertId] = []
        node = self.single_attribute(oids.ATTR_SIGNING_CERTIFICATE_V2)
        if node is not None:
            outer = der.Cursor(node, "signing certificate v2")
            for item in outer.universal(der.SEQUENCE, "certificates").children:
                cursor = der.Cursor(item, "certificate id v2")
                hash_oid = oids.SHA256
                algorithm = cursor.optional_universal(der.SEQUENCE)
                if algorithm is not None:
                    hash_oid = AlgorithmId.parse(algorithm).oid
                found.append(EssCertId(hash_oid, der.octets(cursor.universal(der.OCTET_STRING, "hash"))))
            return found
        node = self.single_attribute(oids.ATTR_SIGNING_CERTIFICATE)
        if node is not None:
            outer = der.Cursor(node, "signing certificate")
            for item in outer.universal(der.SEQUENCE, "certificates").children:
                cursor = der.Cursor(item, "certificate id")
                found.append(EssCertId(oids.SHA1, der.octets(cursor.universal(der.OCTET_STRING, "hash"))))
            return found
        return None


@dataclass
class SignedData:
    version: int
    digest_algorithms: List[AlgorithmId]
    content_type: str
    content: Optional[bytes]
    certificates: List[Certificate] = field(default_factory=list)
    signers: List[SignerInfo] = field(default_factory=list)


def _parse_attributes(raw: bytes) -> Dict[str, List[der.Node]]:
    """Signed attributes must be real DER, because their exact bytes are what is signed."""
    wrapper = der.parse(raw, strict=True)
    attributes: Dict[str, List[der.Node]] = {}
    for item in wrapper.children:
        cursor = der.Cursor(item, "signed attribute")
        oid = der.oid_value(cursor.universal(der.OID, "type"))
        values = cursor.universal(der.SET, "values")
        cursor.finish()
        if oid in attributes:
            raise TokenFormatError(f"signed attribute {oid} appears twice")
        attributes[oid] = list(values.children)
    return attributes


def _algorithm(node: der.Node) -> AlgorithmId:
    if not node.is_universal(der.SEQUENCE):
        raise TokenFormatError("an algorithm identifier must be a sequence")
    return AlgorithmId.parse(node)


def _digest_algorithm(node: der.Node) -> AlgorithmId:
    algorithm = _algorithm(node)
    if not algorithm.has_no_real_params():
        raise TokenFormatError("a digest algorithm identifier must have no parameters")
    return algorithm


def _parse_signer(node: der.Node) -> SignerInfo:
    if not node.is_universal(der.SEQUENCE):
        raise TokenFormatError("signer info must be a sequence")
    cursor = der.Cursor(node, "signer info")
    version = der.int_value(cursor.universal(der.INTEGER, "version"))
    identifier = cursor.next("signer identifier")
    issuer: Optional[Name] = None
    serial: Optional[int] = None
    subject_key_id: Optional[bytes] = None
    if identifier.is_universal(der.SEQUENCE):
        pair = der.Cursor(identifier, "issuer and serial number")
        issuer = Name(pair.universal(der.SEQUENCE, "issuer").raw)
        serial = der.int_value(pair.universal(der.INTEGER, "serial number"))
        pair.finish()
    elif identifier.is_context(0):
        subject_key_id = der.octets(identifier)
    else:
        raise TokenFormatError("signer identifier has an unknown form")
    digest_algorithm = _digest_algorithm(cursor.universal(der.SEQUENCE, "digest algorithm"))
    attrs_node = cursor.optional_context(0)
    attrs_raw = attrs_node.raw if attrs_node is not None else None
    attributes = _parse_attributes(attrs_raw) if attrs_raw is not None else {}
    signature_algorithm = AlgorithmId.parse(cursor.universal(der.SEQUENCE, "signature algorithm"))
    signature = der.octets(cursor.universal(der.OCTET_STRING, "signature"))
    cursor.optional_context(1)
    cursor.finish()
    return SignerInfo(
        version,
        issuer,
        serial,
        subject_key_id,
        digest_algorithm,
        attrs_raw,
        attributes,
        signature_algorithm,
        signature,
    )


def _single_child(node: der.Node, what: str) -> der.Node:
    if len(node.children) != 1:
        raise TokenFormatError(f"{what} must hold exactly one value")
    return node.children[0]


def parse_signed_data(node: der.Node) -> SignedData:
    """Reads a ContentInfo holding SignedData. The node may come from the lenient BER mode."""
    outer = der.Cursor(node, "content info")
    content_type = der.oid_value(outer.universal(der.OID, "content type"))
    if content_type != oids.CMS_SIGNED_DATA:
        raise TokenFormatError(f"expected signed data, found content type {content_type}")
    wrapper = outer.optional_context(0)
    if wrapper is None:
        raise TokenFormatError("signed data content is missing")
    outer.finish()
    body_node = _single_child(wrapper, "signed data wrapper")
    if not body_node.is_universal(der.SEQUENCE):
        raise TokenFormatError("signed data must be a sequence")
    body = der.Cursor(body_node, "signed data")
    version = der.int_value(body.universal(der.INTEGER, "version"))
    digest_set = body.universal(der.SET, "digest algorithms")
    digest_algorithms = [_digest_algorithm(item) for item in digest_set.children]

    encap = der.Cursor(body.universal(der.SEQUENCE, "encapsulated content"), "encapsulated content")
    encap_type = der.oid_value(encap.universal(der.OID, "content type"))
    content: Optional[bytes] = None
    content_wrapper = encap.optional_context(0)
    if content_wrapper is not None:
        value = _single_child(content_wrapper, "encapsulated content wrapper")
        if not value.is_universal(der.OCTET_STRING):
            raise TokenFormatError("encapsulated content is not an octet string")
        content = der.octets(value)
    encap.finish()

    certificates: List[Certificate] = []
    certificates_node = body.optional_context(0)
    if certificates_node is not None:
        for item in certificates_node.children:
            if item.is_universal(der.SEQUENCE):
                certificates.append(Certificate(item.raw))
    body.optional_context(1)
    signer_set = body.universal(der.SET, "signer infos")
    body.finish()
    signers = [_parse_signer(item) for item in signer_set.children]
    return SignedData(version, digest_algorithms, encap_type, content, certificates, signers)


def find_signer_certificate(signer: SignerInfo, certificates: List[Certificate]) -> Optional[Certificate]:
    for cert in certificates:
        if signer.matches_certificate(cert):
            return cert
    return None


def check_signing_cert_attribute(signer: SignerInfo, cert: Certificate) -> Tuple[bool, str]:
    """RFC 3161 requires the signed attributes to bind the signer's exact certificate."""
    ids = signer.signing_cert_ids()
    if ids is None:
        return False, "the signing-certificate attribute RFC 3161 requires is missing"
    if not ids:
        return False, "the signing-certificate attribute lists no certificates"
    first = ids[0]
    algorithm = hashes.by_oid(first.hash_oid)
    if algorithm is None:
        return False, f"the signing-certificate attribute uses unknown hash {first.hash_oid}"
    if algorithm.digest(cert.raw) != first.digest:
        return False, "the signing-certificate attribute names a different certificate"
    return True, f"signing-certificate attribute names this certificate ({algorithm.display})"
