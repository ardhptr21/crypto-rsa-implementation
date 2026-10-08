# RSA QR Ticket

This project implements an offline QR ticket verification system. RSA and its
supporting number-theory operations are implemented in
readable Python. The RSA code has **no third-party dependencies**; only the QR layer (below) uses libraries.

Python standard-library modules are used only for general-purpose facilities:

- `secrets` for operating-system cryptographic randomness
- `hashlib` and `hmac` for SHA-256 and constant-time digest comparison
- `dataclasses`, `json`, and `pathlib` for data structures and files
- `unittest` for tests

The RSA-specific algorithms implemented by this project include:

- Euclidean and extended Euclidean algorithms
- Modular inverse and square-and-multiply exponentiation
- Miller-Rabin probable-prime testing
- RSA key generation using Carmichael's function
- CRT-accelerated and blinded private operations
- RSA-OAEP encryption with SHA-256
- RSA-PSS signatures with SHA-256
- Validated JSON key serialization

## Project layout

```text
src/
  crypto/              RSA implementation package
    number_theory.py   Fundamental integer algorithms
    primes.py          Miller-Rabin and prime generation
    keys.py            RSA keys and primitive operations
    encoding.py        RFC 8017 byte/integer helpers and MGF1
    oaep.py            Safe randomized RSA encryption
    pss.py             Safe randomized RSA signatures
    serialization.py   Readable key persistence
  qrticket/            Signed ticket and QR application package
    ticket.py          Validated ticket data and serialization
    payload.py         Compact canonical QR payload encoding
    issuer.py          Ticket signing and QR issuing
    batch.py           Atomic multi-type ticket batch generation
    verifier.py        Signature, event, and expiry verification
    qr.py              QR image rendering and reading
cli/
  main.py              Interactive batch-generation wizard
tests/                 Standard-library unittest suite
examples/demo.py       End-to-end demonstration
examples/qr_demo.py    QR ticket demonstration
```

The `src` layout prevents accidental imports from the repository root and keeps
application code separate from tests, examples, and project configuration.

## Setup

The recommended setup creates a project-local virtual environment and installs
the optional QR image libraries using the versions recorded in `uv.lock`:

```powershell
uv sync --extra qr
```

The standard `venv` and `pip` workflow is also supported:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[qr]"
```

Installing the project without the `qr` extra installs no runtime dependencies.
The QR tests, CLI, and demo require Segno, ZXing-CPP, and Pillow. The complete
`src/crypto` package uses only Python's standard library and local modules; it
does not import or call any external cryptography library.

## Generate a ticket batch

Start the interactive generator:

```powershell
uv run python cli/main.py
```

The guided wizard asks for the event, expiration date, output directory,
private-key location, and any ticket types required by that event. Ticket types
are entered dynamically and are not restricted to predefined names. Examples
include Standard, Gold, Platinum, Student, VIP, Press, or Backstage.

Each run receives a random batch id so ticket ids do not repeat when another
batch is generated for the same event. A completed output directory looks like:

```text
output/university-expo/
  manifest.csv
  public-key.json
  qr/
    UNIVERSITY-EXPO-STANDARD-A1B2C3D4E5F60708-0001.png
    UNIVERSITY-EXPO-GOLD-A1B2C3D4E5F60708-0001.png
```

The CSV manifest lists the batch id, ticket id, event, expiration date, ticket
type, and QR filename. The public key can be distributed to scanners. The
unencrypted private key is stored separately under `keys/` by default and must
not be shared.

Batch generation is also available as a Python API:

```python
from datetime import date
from crypto import generate_key_pair
from qrticket import TicketType, issue_ticket_batch

_, private_key = generate_key_pair()
result = issue_ticket_batch(
    event="University Expo",
    valid_until=date(2027, 12, 31),
    ticket_types=(
        TicketType("STANDARD", 100),
        TicketType("GOLD", 25),
        TicketType("PLATINUM", 5),
    ),
    private_key=private_key,
    output_directory="output/university-expo",
)
print(result.total)
```

## Run the tests

From this directory:

```powershell
uv run python -m unittest discover -s tests -v
```

## Run the demonstration

```powershell
uv run python examples/demo.py
```

The demonstration generates a new 2048-bit key, performs an OAEP encryption
round trip, signs ticket data using PSS, and proves that a modified ticket does
not validate.

## Minimal API

```python
from crypto import generate_key_pair, sign_pss, verify_pss

public_key, private_key = generate_key_pair()

ticket = b"V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT"
signature = sign_pss(ticket, private_key)

assert verify_pss(ticket, signature, public_key)
assert not verify_pss(ticket + b"|VIP", signature, public_key)
```

## Scope and security note

The implementation follows the OAEP and PSS structures from RFC 8017, but it
has not received professional cryptographic review. Python integer operations
are not guaranteed to execute in constant time. This makes the package suitable
for learning, assessment, and the university prototype, but not for protecting
production systems.

The private-key JSON format is deliberately readable and currently unencrypted.
Keep private-key files confidential. Public keys are safe to distribute to QR
ticket validators.

## QR tickets

The `qrticket` package turns the RSA layer into a ticket system: sign a ticket,
put it in a QR code, and verify it later using only the public key. RSA itself
still uses no third-party code; the QR image libraries (`segno`, `zxing-cpp`,
`Pillow`) are used only to draw and read the QR picture.

A ticket is five fields: `V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT`
(version, ticket id, event, valid-until date, category). The QR code holds
`RQT1.<ticket>.<signature>` with both parts base64url-encoded.

```python
from datetime import date
from crypto import generate_key_pair
from qrticket import Ticket, issue_ticket_qr, verify_qr_image

public_key, private_key = generate_key_pair()
ticket = Ticket("TKT-0001", "EVENT-2026", date(2026, 12, 31), "STUDENT")
issue_ticket_qr(ticket, private_key, "ticket.png")

result = verify_qr_image(
    "ticket.png",
    public_key,
    expected_event="EVENT-2026",
)
print(result.status)   # VerifyStatus.VALID
```

Verification checks, in order: the payload format, the RSA-PSS signature, the
ticket fields, the expected event when supplied, and that today is not past the
valid-until date (inclusive). Possible results: `VALID`, `BAD_FORMAT`,
`BAD_SIGNATURE`, `WRONG_EVENT`, `EXPIRED`, `UNREADABLE_QR`.

Limitation: verification is fully offline, so a photographed or copied QR code
passes as many times as it is scanned. Catching reuse needs a shared list of
used ticket ids, which this project does not include.

Run the demo with `uv run python examples/qr_demo.py`.
