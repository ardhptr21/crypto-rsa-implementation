from dataclasses import dataclass
from datetime import date
from enum import Enum
from pathlib import Path

from crypto import RSAPublicKey, verify_pss

from .errors import PayloadFormatError, QRReadError, TicketFormatError
from .payload import decode_payload
from .ticket import Ticket, parse_ticket


class VerifyStatus(Enum):
    VALID = "valid"
    BAD_FORMAT = "bad_format"
    BAD_SIGNATURE = "bad_signature"
    WRONG_EVENT = "wrong_event"
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
    expected_event: str | None = None,
) -> VerificationResult:
    if today is None:
        today = date.today()
    elif type(today) is not date:
        raise TypeError("today must be a date")
    if expected_event is not None and not isinstance(expected_event, str):
        raise TypeError("expected_event must be a string or None")

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

    if expected_event is not None and ticket.event != expected_event:
        return VerificationResult(VerifyStatus.WRONG_EVENT, ticket)
    if today > ticket.valid_until:
        return VerificationResult(VerifyStatus.EXPIRED, ticket)
    return VerificationResult(VerifyStatus.VALID, ticket)


def verify_qr_image(
    path: str | Path,
    public_key: RSAPublicKey,
    today: date | None = None,
    expected_event: str | None = None,
) -> VerificationResult:
    from .qr import read_qr

    try:
        text = read_qr(path)
    except QRReadError:
        return VerificationResult(VerifyStatus.UNREADABLE_QR)
    return verify_payload(text, public_key, today, expected_event)
