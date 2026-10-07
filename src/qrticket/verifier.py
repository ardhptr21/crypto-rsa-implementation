from dataclasses import dataclass
from datetime import date
from enum import Enum
from pathlib import Path

from crypto import RSAPublicKey, verify_pss

from .errors import PayloadFormatError, QRReadError, TicketFormatError
from .payload import decode_payload
from .qr import read_qr
from .ticket import Ticket, parse_ticket


class VerifyStatus(Enum):
    VALID = "valid"
    BAD_FORMAT = "bad_format"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    UNREADABLE_QR = "unreadable_qr"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: VerifyStatus
    ticket: Ticket | None = None

    @property
    def valid(self) -> bool:
        return self.status is VerifyStatus.VALID


def verify_payload(
    text: str,
    public_key: RSAPublicKey,
    today: date | None = None,
) -> VerificationResult:
    if today is None:
        today = date.today()
    elif type(today) is not date:
        raise TypeError("today must be a date")

    try:
        ticket_bytes, signature = decode_payload(text)
    except PayloadFormatError:
        return VerificationResult(VerifyStatus.BAD_FORMAT)

    if not verify_pss(ticket_bytes, signature, public_key):
        return VerificationResult(VerifyStatus.BAD_SIGNATURE)

    try:
        ticket = parse_ticket(ticket_bytes)
    except TicketFormatError:
        return VerificationResult(VerifyStatus.BAD_FORMAT)

    if today > ticket.valid_until:
        return VerificationResult(VerifyStatus.EXPIRED, ticket)
    return VerificationResult(VerifyStatus.VALID, ticket)


def verify_qr_image(
    path: str | Path,
    public_key: RSAPublicKey,
    today: date | None = None,
) -> VerificationResult:
    try:
        text = read_qr(path)
    except QRReadError:
        return VerificationResult(VerifyStatus.UNREADABLE_QR)
    return verify_payload(text, public_key, today)
