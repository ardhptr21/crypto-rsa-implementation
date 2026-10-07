import base64
import binascii
import re

from .errors import PayloadFormatError


PREFIX = "RQT1"
SEPARATOR = "."

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


def _encode_part(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_part(text: str) -> bytes:
    if not _BASE64URL.fullmatch(text) or len(text) % 4 == 1:
        raise PayloadFormatError("payload part is not valid base64url")
    padded = text + "=" * (-len(text) % 4)
    try:
        data = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as error:
        raise PayloadFormatError("payload part is not valid base64url") from error
    if _encode_part(data) != text:
        raise PayloadFormatError("payload part is not canonical base64url")
    return data


def encode_payload(ticket_bytes: bytes, signature: bytes) -> str:
    if not isinstance(ticket_bytes, bytes) or not isinstance(signature, bytes):
        raise TypeError("ticket and signature must be bytes")
    if not ticket_bytes or not signature:
        raise PayloadFormatError("ticket and signature must not be empty")
    return SEPARATOR.join(
        (PREFIX, _encode_part(ticket_bytes), _encode_part(signature))
    )


def decode_payload(text: str) -> tuple[bytes, bytes]:
    if not isinstance(text, str):
        raise TypeError("payload must be a string")
    parts = text.split(SEPARATOR)
    if len(parts) != 3 or parts[0] != PREFIX:
        raise PayloadFormatError("payload must look like RQT1.<ticket>.<signature>")
    return _decode_part(parts[1]), _decode_part(parts[2])
