import argparse
from collections.abc import Callable
from datetime import date
from pathlib import Path

from crypto import (
    DEFAULT_KEY_BITS,
    RSAPrivateKey,
    generate_key_pair,
    load_private_key,
    save_private_key,
    save_public_key,
)

from .batch import ProgressFunction, TicketType, issue_ticket_batch, slugify
from .ticket import Ticket


InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]
SCREEN_WIDTH = 62


def _print_banner(output_fn: OutputFunction) -> None:
    output_fn("=" * SCREEN_WIDTH)
    output_fn("RSA QR TICKET BATCH GENERATOR".center(SCREEN_WIDTH))
    subtitle = "Create signed QR tickets for any event and ticket type"
    output_fn(subtitle.center(SCREEN_WIDTH))
    output_fn("=" * SCREEN_WIDTH)


def _print_section(number: int, title: str, output_fn: OutputFunction) -> None:
    output_fn("")
    output_fn(f"[{number}/4] {title}")
    output_fn("-" * SCREEN_WIDTH)


def _print_ticket_table(
    ticket_types: tuple[TicketType, ...],
    output_fn: OutputFunction,
) -> None:
    name_width = max(len("Ticket type"), *(len(item.name) for item in ticket_types))
    quantity_width = max(
        len("Quantity"),
        *(len(str(item.quantity)) for item in ticket_types),
    )
    border = f"+-{'-' * name_width}-+-{'-' * quantity_width}-+"
    output_fn(border)
    output_fn(
        f"| {'Ticket type':<{name_width}} | {'Quantity':>{quantity_width}} |"
    )
    output_fn(border)
    for item in ticket_types:
        output_fn(f"| {item.name:<{name_width}} | {item.quantity:>{quantity_width}} |")
    output_fn(border)


def _prompt_required(
    prompt: str,
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> str:
    while True:
        value = input_fn(prompt).strip()
        if value:
            return value
        output_fn("A value is required.")


def _prompt_event(input_fn: InputFunction, output_fn: OutputFunction) -> str:
    while True:
        event = _prompt_required("Event name or ID: ", input_fn, output_fn)
        try:
            Ticket("VALIDATION", event, date.max, "VALIDATION")
            slugify(event)
        except (TypeError, ValueError) as error:
            output_fn(f"Invalid event: {error}")
            continue
        return event


def _prompt_date(input_fn: InputFunction, output_fn: OutputFunction) -> date:
    while True:
        value = input_fn("Valid until (YYYY-MM-DD): ").strip()
        try:
            valid_until = date.fromisoformat(value)
        except ValueError:
            output_fn("Enter a real date in YYYY-MM-DD format.")
            continue
        if valid_until < date.today():
            output_fn("The expiration date cannot be in the past.")
            continue
        return valid_until


def _prompt_quantity(
    ticket_type: str,
    input_fn: InputFunction,
    output_fn: OutputFunction,
    minimum: int = 0,
) -> int:
    while True:
        default = " [0]" if minimum == 0 else ""
        value = input_fn(f"Number of {ticket_type} tickets{default}: ").strip()
        if not value and minimum == 0:
            value = "0"
        try:
            quantity = int(value)
        except ValueError:
            output_fn("Quantity must be a whole number.")
            continue
        if quantity < minimum:
            output_fn(f"Quantity must be at least {minimum}.")
            continue
        return quantity


def _prompt_yes_no(
    prompt: str,
    input_fn: InputFunction,
    default: bool = False,
) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        value = input_fn(prompt + suffix).strip().casefold()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False


def _collect_ticket_types(
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> tuple[TicketType, ...]:
    ticket_types: list[TicketType] = []
    names: set[str] = set()
    slugs: set[str] = set()

    output_fn("Enter any ticket types required by this event.")
    output_fn("Examples: General Admission, VIP, Student, Backstage")

    while True:
        position = len(ticket_types) + 1
        name = _prompt_required(
            f"Ticket type {position} name: ",
            input_fn,
            output_fn,
        )
        try:
            ticket_type = TicketType(name, 1)
            type_slug = slugify(name)
        except (TypeError, ValueError) as error:
            output_fn(f"Invalid ticket type: {error}")
            continue
        if name.casefold() in names or type_slug in slugs:
            output_fn("That ticket type was already added.")
            continue

        quantity = _prompt_quantity(name, input_fn, output_fn, minimum=1)
        ticket_types.append(TicketType(ticket_type.name, quantity))
        names.add(name.casefold())
        slugs.add(type_slug)

        if not _prompt_yes_no("Add another ticket type?", input_fn):
            return tuple(ticket_types)


def _default_paths(event: str) -> tuple[Path, Path]:
    slug = slugify(event).lower()
    return Path("output") / slug, Path("keys") / f"{slug}.private.json"


def _public_key_path(private_key_path: Path) -> Path:
    suffix = ".private.json"
    if private_key_path.name.endswith(suffix):
        name = private_key_path.name[: -len(suffix)] + ".public.json"
    else:
        name = private_key_path.stem + ".public.json"
    return private_key_path.with_name(name)


def _load_or_create_key(
    private_key_path: Path,
    key_bits: int,
    output_fn: OutputFunction,
) -> tuple[RSAPrivateKey, Path]:
    if private_key_path.exists():
        output_fn(f"Loading private key: {private_key_path}")
        private_key = load_private_key(private_key_path)
    else:
        output_fn(f"Generating a {key_bits}-bit RSA key pair...")
        _, private_key = generate_key_pair(bits=key_bits)
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        save_private_key(private_key, private_key_path)

    public_key_path = _public_key_path(private_key_path)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    save_public_key(private_key.public_key, public_key_path)
    return private_key, public_key_path


def _make_progress_reporter(output_fn: OutputFunction) -> ProgressFunction:
    previous_bucket = -1

    def report(completed: int, total: int, ticket: Ticket) -> None:
        nonlocal previous_bucket
        percent = completed * 100 // total
        bucket = min(percent // 10, 10)
        if bucket == previous_bucket and completed != total:
            return
        previous_bucket = bucket
        bar = "=" * bucket + "-" * (10 - bucket)
        output_fn(f"[{bar}] {completed}/{total} ({percent}%)")

    return report


def run_interactive(
    key_bits: int = DEFAULT_KEY_BITS,
    input_fn: InputFunction | None = None,
    output_fn: OutputFunction | None = None,
) -> int:
    input_fn = input if input_fn is None else input_fn
    output_fn = print if output_fn is None else output_fn

    _print_banner(output_fn)
    _print_section(1, "EVENT DETAILS", output_fn)
    event = _prompt_event(input_fn, output_fn)
    valid_until = _prompt_date(input_fn, output_fn)
    default_output, default_private_key = _default_paths(event)

    _print_section(2, "FILES AND KEYS", output_fn)
    while True:
        output_value = input_fn(f"Output directory [{default_output}]: ").strip()
        output_directory = Path(output_value) if output_value else default_output
        if not output_directory.exists():
            break
        output_fn("That output directory already exists. Choose another directory.")

    key_value = input_fn(f"Private key file [{default_private_key}]: ").strip()
    private_key_path = Path(key_value) if key_value else default_private_key
    if private_key_path.exists():
        output_fn("An existing private key will be reused.")
    else:
        output_fn(f"A new {key_bits}-bit RSA key pair will be generated.")

    _print_section(3, "TICKET TYPES", output_fn)
    ticket_types = _collect_ticket_types(input_fn, output_fn)
    total = sum(ticket_type.quantity for ticket_type in ticket_types)

    _print_section(4, "REVIEW AND GENERATE", output_fn)
    output_fn(f"Event: {event}")
    output_fn(f"Valid until: {valid_until.isoformat()}")
    output_fn("")
    _print_ticket_table(ticket_types, output_fn)
    output_fn("")
    output_fn(f"Total tickets: {total}")
    output_fn(f"Output directory: {output_directory}")
    output_fn(f"Private key: {private_key_path}")
    output_fn("The private key is stored as unencrypted JSON and must remain secret.")

    if not _prompt_yes_no("Generate these tickets?", input_fn):
        output_fn("Cancelled.")
        return 0

    try:
        private_key, public_key_path = _load_or_create_key(
            private_key_path,
            key_bits,
            output_fn,
        )
        result = issue_ticket_batch(
            event=event,
            valid_until=valid_until,
            ticket_types=ticket_types,
            private_key=private_key,
            output_directory=output_directory,
            progress=_make_progress_reporter(output_fn),
        )
    except (OSError, TypeError, ValueError) as error:
        output_fn(f"Generation failed: {error}")
        return 1

    output_fn("")
    output_fn("=" * SCREEN_WIDTH)
    output_fn("GENERATION COMPLETE".center(SCREEN_WIDTH))
    output_fn("=" * SCREEN_WIDTH)
    output_fn(f"Generated tickets: {result.total}")
    output_fn(f"Batch ID: {result.batch_id}")
    output_fn(f"QR files: {result.output_directory / 'qr'}")
    output_fn(f"Manifest: {result.manifest_path}")
    output_fn(f"Verification key: {result.public_key_path}")
    output_fn(f"Issuer public key: {public_key_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate RSA-signed QR tickets")
    parser.add_argument("--key-bits", type=int, default=DEFAULT_KEY_BITS)
    arguments = parser.parse_args(argv)
    try:
        return run_interactive(key_bits=arguments.key_bits)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 130
