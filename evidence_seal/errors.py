"""Exception types shared across the package."""


class EvidenceSealError(Exception):
    """Base class for every error this package raises on purpose."""


class DerError(EvidenceSealError):
    """Bytes that are not valid DER (or BER, where BER is allowed)."""


class TokenFormatError(EvidenceSealError):
    """Well formed bytes that do not make up the expected ASN.1 structure."""


class CertificateFileError(EvidenceSealError):
    """A certificate file that could not be read or holds no certificates."""


class ManifestError(EvidenceSealError):
    """A manifest that cannot be written or read at all."""


class SealError(EvidenceSealError):
    """A folder that cannot be sealed truthfully."""


class StampError(EvidenceSealError):
    """A timestamp request that did not produce a usable token."""


class UsageError(EvidenceSealError):
    """Bad arguments that argparse cannot catch by itself."""
