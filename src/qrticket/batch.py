from collections.abc import Callable, Sequence
import csv
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from crypto import RSAPrivateKey, save_public_key

from .errors import TicketFormatError
from .event import EventProfile, public_key_fingerprint, save_event_profile
from .issuer import issue_ticket_qr
from .ticket import Ticket


ProgressFunction = Callable[[int, int, Ticket], None]


@dataclass(frozen=True, slots=True)
class TicketType:
    name: str
    quantity: int

    def __post_init__(self) -> None:
        Ticket("VALIDATION", "VALIDATION", date.max, self.name)
        if isinstance(self.quantity, bool) or not isinstance(self.quantity, int):
            raise TypeError("ticket quantity must be an integer")
        if self.quantity <= 0:
            raise ValueError("ticket quantity must be positive")


@dataclass(frozen=True, slots=True)
class BatchResult:
    batch_id: str
    output_directory: Path
    manifest_path: Path
    public_key_path: Path
    event_profile_path: Path
    tickets: tuple[Ticket, ...]

    @property
    def total(self) -> int:
        return len(self.tickets)


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").upper()
    if not slug:
        raise TicketFormatError("value must contain at least one letter or number")
    return slug


def _validate_ticket_types(ticket_types: Sequence[TicketType]) -> None:
    if not isinstance(ticket_types, Sequence) or isinstance(ticket_types, (str, bytes)):
        raise TypeError("ticket_types must be a sequence of TicketType values")
    if not ticket_types:
        raise ValueError("at least one ticket type is required")

    names: set[str] = set()
    slugs: set[str] = set()
    for ticket_type in ticket_types:
        if not isinstance(ticket_type, TicketType):
            raise TypeError("ticket_types must contain only TicketType values")
        name = ticket_type.name.casefold()
        slug = slugify(ticket_type.name)
        if name in names or slug in slugs:
            raise ValueError(f"duplicate ticket type {ticket_type.name!r}")
        names.add(name)
        slugs.add(slug)


def issue_ticket_batch(
    event: str,
    valid_until: date,
    ticket_types: Sequence[TicketType],
    private_key: RSAPrivateKey,
    output_directory: str | Path,
    batch_id: str | None = None,
    progress: ProgressFunction | None = None,
) -> BatchResult:
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("private_key must be an RSAPrivateKey")
    if progress is not None and not callable(progress):
        raise TypeError("progress must be callable or None")
    _validate_ticket_types(ticket_types)

    event_slug = slugify(event)
    batch_id = slugify(secrets.token_hex(8) if batch_id is None else batch_id)
    Ticket("VALIDATION", event, valid_until, ticket_types[0].name)

    destination = Path(output_directory)
    if destination.exists():
        raise FileExistsError(f"output directory already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent)
    )
    tickets: list[Ticket] = []
    total = sum(ticket_type.quantity for ticket_type in ticket_types)

    try:
        qr_directory = temporary / "qr"
        qr_directory.mkdir()
        manifest_path = temporary / "manifest.csv"

        with manifest_path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=(
                    "ticket_id",
                    "batch_id",
                    "event",
                    "valid_until",
                    "ticket_type",
                    "qr_file",
                ),
            )
            writer.writeheader()

            for ticket_type in ticket_types:
                type_slug = slugify(ticket_type.name)
                for number in range(1, ticket_type.quantity + 1):
                    ticket_id = (
                        f"{event_slug}-{type_slug}-{batch_id}-{number:04d}"
                    )
                    ticket = Ticket(
                        ticket_id=ticket_id,
                        event=event,
                        valid_until=valid_until,
                        category=ticket_type.name,
                    )
                    qr_name = f"{ticket_id}.png"
                    issue_ticket_qr(ticket, private_key, qr_directory / qr_name)
                    writer.writerow(
                        {
                            "ticket_id": ticket.ticket_id,
                            "batch_id": batch_id,
                            "event": ticket.event,
                            "valid_until": ticket.valid_until.isoformat(),
                            "ticket_type": ticket.category,
                            "qr_file": f"qr/{qr_name}",
                        }
                    )
                    tickets.append(ticket)
                    if progress is not None:
                        progress(len(tickets), total, ticket)

        public_key_file = "public-key.json"
        save_public_key(private_key.public_key, temporary / public_key_file)
        profile = EventProfile(
            event=event,
            valid_until=valid_until,
            batch_id=batch_id,
            public_key_file=public_key_file,
            public_key_fingerprint=public_key_fingerprint(private_key.public_key),
        )
        save_event_profile(profile, temporary / "event.json")
        temporary.replace(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return BatchResult(
        batch_id=batch_id,
        output_directory=destination,
        manifest_path=destination / "manifest.csv",
        public_key_path=destination / "public-key.json",
        event_profile_path=destination / "event.json",
        tickets=tuple(tickets),
    )
