"""RFC 3161 structures: the timestamp request, the response and TSTInfo."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from . import cms, der, oids
from .errors import TokenFormatError
from .hashes import HashAlgorithm
from .signatures import AlgorithmId
from .x509 import Name

MAX_TOKEN_BYTES = 4 * 1024 * 1024

STATUS_GRANTED = 0
STATUS_GRANTED_WITH_MODS = 1
STATUS_NAMES = {
    0: "granted",
    1: "granted with modifications",
    2: "rejected",
    3: "waiting",
    4: "revocation warning",
    5: "revoked",
}
FAILURE_NAMES = {
    0: "unsupported hash algorithm",
    2: "malformed request",
    5: "unexpected data format",
    14: "the authority's time source is unavailable",
    15: "requested policy is not supported",
    16: "requested extension is not supported",
    17: "requested additional information is not available",
    25: "system failure at the authority",
}


@dataclass
class TimeStampRequest:
    version: int
    hash_oid: str
    digest: bytes
    policy: Optional[str]
    nonce: Optional[int]
    cert_req: bool
    extensions: bool = False


def build_request(
    algorithm: HashAlgorithm,
    digest: bytes,
    nonce: Optional[int] = None,
    cert_req: bool = True,
    policy: Optional[str] = None,
) -> bytes:
    """Encodes a TimeStampReq."""
    parts = [
        der.encode_int(1),
        der.encode_seq(der.encode_seq(der.encode_oid(algorithm.oid), der.encode_null()), der.encode_octets(digest)),
    ]
    if policy is not None:
        parts.append(der.encode_oid(policy))
    if nonce is not None:
        parts.append(der.encode_int(nonce))
    if cert_req:
        parts.append(der.encode_bool(True))
    return der.encode_seq(*parts)


def parse_request(data: bytes) -> TimeStampRequest:
    cursor = der.Cursor(der.parse(data), "timestamp request")
    version = der.int_value(cursor.universal(der.INTEGER, "version"))
    imprint = der.Cursor(cursor.universal(der.SEQUENCE, "message imprint"), "message imprint")
    hash_oid = AlgorithmId.parse(imprint.universal(der.SEQUENCE, "hash algorithm")).oid
    digest = der.octets(imprint.universal(der.OCTET_STRING, "hash"))
    imprint.finish()
    policy_node = cursor.optional_universal(der.OID)
    nonce_node = cursor.optional_universal(der.INTEGER)
    cert_node = cursor.optional_universal(der.BOOLEAN)
    extensions = cursor.optional_context(0)
    cursor.finish()
    return TimeStampRequest(
        version,
        hash_oid,
        digest,
        der.oid_value(policy_node) if policy_node is not None else None,
        der.int_value(nonce_node) if nonce_node is not None else None,
        der.bool_value(cert_node) if cert_node is not None else False,
        extensions is not None,
    )


@dataclass
class TstInfo:
    raw: bytes
    version: int
    policy: str
    hash_oid: str
    digest: bytes
    serial: int
    gen_time: datetime
    accuracy_seconds: Optional[int] = None
    accuracy_millis: Optional[int] = None
    accuracy_micros: Optional[int] = None
    ordering: bool = False
    nonce: Optional[int] = None
    tsa_name: Optional[Name] = None
    tsa_text: Optional[str] = None
    extension_oids: List[str] = field(default_factory=list)

    def accuracy_text(self) -> str:
        if self.accuracy_seconds is None and self.accuracy_millis is None and self.accuracy_micros is None:
            return "accuracy not stated"
        parts = []
        if self.accuracy_seconds:
            parts.append(f"{self.accuracy_seconds} s")
        if self.accuracy_millis:
            parts.append(f"{self.accuracy_millis} ms")
        if self.accuracy_micros:
            parts.append(f"{self.accuracy_micros} us")
        return "accurate to plus or minus " + (" ".join(parts) if parts else "0 s")

    def authority_text(self) -> Optional[str]:
        if self.tsa_name is not None:
            return self.tsa_name.display()
        return self.tsa_text


def parse_tst_info(data: bytes) -> TstInfo:
    """TSTInfo is what the authority signs, so only strict DER is accepted."""
    cursor = der.Cursor(der.parse(data, strict=True), "TSTInfo")
    version = der.int_value(cursor.universal(der.INTEGER, "version"))
    policy = der.oid_value(cursor.universal(der.OID, "policy"))
    imprint = der.Cursor(cursor.universal(der.SEQUENCE, "message imprint"), "message imprint")
    hash_oid = AlgorithmId.parse(imprint.universal(der.SEQUENCE, "hash algorithm")).oid
    digest = der.octets(imprint.universal(der.OCTET_STRING, "hash"))
    imprint.finish()
    serial = der.int_value(cursor.universal(der.INTEGER, "serial number"))
    gen_time_node = cursor.universal(der.GENERALIZED_TIME, "time")
    info = TstInfo(data, version, policy, hash_oid, digest, serial, der.time_value(gen_time_node))
    accuracy = cursor.optional_universal(der.SEQUENCE)
    if accuracy is not None:
        inner = der.Cursor(accuracy, "accuracy")
        seconds = inner.optional_universal(der.INTEGER)
        info.accuracy_seconds = der.int_value(seconds) if seconds is not None else 0
        millis = inner.optional_context(0)
        micros = inner.optional_context(1)
        inner.finish()
        if millis is not None:
            info.accuracy_millis = int.from_bytes(millis.content, "big")
        if micros is not None:
            info.accuracy_micros = int.from_bytes(micros.content, "big")
    ordering = cursor.optional_universal(der.BOOLEAN)
    if ordering is not None:
        info.ordering = der.bool_value(ordering)
    nonce = cursor.optional_universal(der.INTEGER)
    if nonce is not None:
        info.nonce = der.int_value(nonce)
    tsa = cursor.optional_context(0)
    if tsa is not None:
        _read_tsa_name(tsa, info)
    extensions = cursor.optional_context(1)
    cursor.finish()
    if extensions is not None:
        for item in extensions.children:
            info.extension_oids.append(der.oid_value(der.Cursor(item, "extension").universal(der.OID, "identifier")))
    return info


def _read_tsa_name(wrapper: der.Node, info: TstInfo) -> None:
    if len(wrapper.children) != 1:
        raise TokenFormatError("the authority name field must hold one name")
    name = wrapper.children[0]
    if name.is_context(4) and len(name.children) == 1:
        info.tsa_name = Name(name.children[0].raw)
    elif name.cls == der.CONTEXT and not name.constructed:
        info.tsa_text = name.content.decode("latin-1")
    else:
        info.tsa_text = "(a name form this tool does not read)"


@dataclass
class TimeStampResponse:
    """A parsed response or a bare token. ``status`` is None for a bare token."""

    raw: bytes
    status: Optional[int]
    status_strings: List[str]
    failure_bits: List[int]
    is_bare_token: bool
    token_raw: Optional[bytes] = None
    signed_data: Optional[cms.SignedData] = None
    tst_info: Optional[TstInfo] = None

    @property
    def granted(self) -> bool:
        return self.status in (None, STATUS_GRANTED, STATUS_GRANTED_WITH_MODS)

    def status_text(self) -> str:
        if self.status is None:
            return "not recorded (this file is a bare token, without the response wrapper)"
        return STATUS_NAMES.get(self.status, f"unknown status {self.status}")

    def failure_text(self) -> str:
        parts = [FAILURE_NAMES.get(bit, f"failure code {bit}") for bit in self.failure_bits]
        parts.extend(self.status_strings)
        return "; ".join(parts)


def parse_response(data: bytes) -> TimeStampResponse:
    """Reads either a TimeStampResp or a bare TimeStampToken."""
    if len(data) > MAX_TOKEN_BYTES:
        raise TokenFormatError(f"file is {len(data)} bytes, far too large to be a timestamp token")
    top = der.parse(data, strict=False)
    if not top.is_universal(der.SEQUENCE) or not top.children:
        raise TokenFormatError("this is not a timestamp response or token")
    first = top.children[0]
    if first.is_universal(der.OID):
        return _with_token(TimeStampResponse(data, None, [], [], True), top)
    cursor = der.Cursor(top, "timestamp response")
    status_node = der.Cursor(cursor.universal(der.SEQUENCE, "status"), "status")
    status = der.int_value(status_node.universal(der.INTEGER, "status code"))
    strings: List[str] = []
    strings_node = status_node.optional_universal(der.SEQUENCE)
    if strings_node is not None:
        strings = [der.text_value(child) for child in strings_node.children]
    failure_bits: List[int] = []
    failure_node = status_node.optional_universal(der.BIT_STRING)
    if failure_node is not None:
        failure_bits = sorted(der.bit_flags(failure_node))
    status_node.finish()
    response = TimeStampResponse(data, status, strings, failure_bits, False)
    token = cursor.optional_universal(der.SEQUENCE)
    cursor.finish()
    if token is not None:
        _with_token(response, token)
    return response


def _with_token(response: TimeStampResponse, token: der.Node) -> TimeStampResponse:
    response.token_raw = token.raw
    signed = cms.parse_signed_data(token)
    response.signed_data = signed
    if signed.content_type != oids.CT_TST_INFO:
        raise TokenFormatError(f"signed content is {signed.content_type}, not a timestamp")
    if signed.content is None:
        raise TokenFormatError("the token carries no timestamp content")
    response.tst_info = parse_tst_info(signed.content)
    return response
