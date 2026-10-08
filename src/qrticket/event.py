from dataclasses import dataclass
from datetime import date
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from crypto import RSAPublicKey

from .errors import TicketFormatError
from .ticket import Ticket


EVENT_PROFILE_FORMAT = "rsa-qr-ticket-event"
EVENT_PROFILE_VERSION = 1
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


def public_key_fingerprint(public_key: RSAPublicKey) -> str:
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("public_key must be an RSAPublicKey")
    data = f"{public_key.n:x}:{public_key.e:x}".encode("ascii")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class EventProfile:
    event: str
    valid_until: date
    batch_id: str
    public_key_file: str
    public_key_fingerprint: str

    def __post_init__(self) -> None:
        try:
            Ticket("VALIDATION", self.event, self.valid_until, "VALIDATION")
            Ticket("VALIDATION", "VALIDATION", date.max, self.batch_id)
        except TicketFormatError as error:
            raise ValueError(str(error)) from error
        if not isinstance(self.public_key_file, str) or not self.public_key_file:
            raise ValueError("public_key_file must be a non-empty string")
        key_path = Path(self.public_key_file)
        if not key_path.name or key_path.is_absolute() or ".." in key_path.parts:
            raise ValueError("public_key_file must stay inside the event directory")
        if (
            not isinstance(self.public_key_fingerprint, str)
            or not _FINGERPRINT.fullmatch(self.public_key_fingerprint)
        ):
            raise ValueError(
                "public_key_fingerprint must be a SHA-256 hexadecimal value"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": EVENT_PROFILE_FORMAT,
            "version": EVENT_PROFILE_VERSION,
            "event": self.event,
            "valid_until": self.valid_until.isoformat(),
            "batch_id": self.batch_id,
            "public_key": self.public_key_file,
            "public_key_fingerprint": self.public_key_fingerprint,
        }


def event_profile_from_dict(data: dict[str, Any]) -> EventProfile:
    if not isinstance(data, dict):
        raise ValueError("event profile must contain a JSON object")
    if data.get("format") != EVENT_PROFILE_FORMAT:
        raise ValueError("unsupported event profile format")
    if data.get("version") != EVENT_PROFILE_VERSION:
        raise ValueError("unsupported event profile version")

    valid_until_value = data.get("valid_until")
    if not isinstance(valid_until_value, str):
        raise ValueError("valid_until must be a date string")
    try:
        valid_until = date.fromisoformat(valid_until_value)
    except ValueError as error:
        raise ValueError("valid_until must use YYYY-MM-DD format") from error

    return EventProfile(
        event=data.get("event"),
        valid_until=valid_until,
        batch_id=data.get("batch_id"),
        public_key_file=data.get("public_key"),
        public_key_fingerprint=data.get("public_key_fingerprint"),
    )


def save_event_profile(profile: EventProfile, path: str | Path) -> None:
    if not isinstance(profile, EventProfile):
        raise TypeError("profile must be an EventProfile")
    Path(path).write_text(
        json.dumps(profile.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )


def load_event_profile(path: str | Path) -> EventProfile:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return event_profile_from_dict(data)
