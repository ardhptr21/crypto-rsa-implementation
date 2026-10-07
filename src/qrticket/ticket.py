from dataclasses import dataclass
from datetime import date
import re

from .errors import TicketFormatError


VERSION = "V1"
SEPARATOR = "|"

_TEXT_FIELD = re.compile(r"[ -~]+")
_DATE_FIELD = re.compile(r"\d{4}-\d{2}-\d{2}")


def _check_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not _TEXT_FIELD.fullmatch(value):
        raise TicketFormatError(f"{name} must be non-empty printable ASCII")
    if SEPARATOR in value:
        raise TicketFormatError(f"{name} must not contain {SEPARATOR!r}")


@dataclass(frozen=True, slots=True)
class Ticket:
    ticket_id: str
    event: str
    valid_until: date
    category: str
    version: str = VERSION

    def __post_init__(self) -> None:
        if self.version != VERSION:
            raise TicketFormatError(f"unsupported ticket version {self.version!r}")
        _check_text("ticket_id", self.ticket_id)
        _check_text("event", self.event)
        _check_text("category", self.category)
        if type(self.valid_until) is not date:
            raise TicketFormatError("valid_until must be a date")

    def to_bytes(self) -> bytes:
        return SEPARATOR.join(
            (
                self.version,
                self.ticket_id,
                self.event,
                self.valid_until.isoformat(),
                self.category,
            )
        ).encode("ascii")


def parse_ticket(data: bytes) -> Ticket:
    if not isinstance(data, bytes):
        raise TypeError("ticket data must be bytes")

    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise TicketFormatError("ticket must be ASCII") from error

    parts = text.split(SEPARATOR)
    if len(parts) != 5:
        raise TicketFormatError("ticket must have exactly 5 fields")
    version, ticket_id, event, date_text, category = parts

    if not _DATE_FIELD.fullmatch(date_text):
        raise TicketFormatError("date must be YYYY-MM-DD")
    try:
        valid_until = date.fromisoformat(date_text)
    except ValueError as error:
        raise TicketFormatError("date is not a real calendar date") from error

    return Ticket(
        ticket_id=ticket_id,
        event=event,
        valid_until=valid_until,
        category=category,
        version=version,
    )
