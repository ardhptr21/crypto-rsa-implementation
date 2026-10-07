# RSA QR Ticket

This is the first implementation layer for the offline QR ticket verification
system. RSA and its supporting number-theory operations are implemented in
readable Python. The project has **no third-party dependencies**.

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
tests/                 Standard-library unittest suite
examples/demo.py       End-to-end demonstration
```

The `src` layout prevents accidental imports from the repository root and keeps
application code separate from tests, examples, and project configuration.

## Setup

The tests and example run directly from a source checkout. An editable install
is optional and does not install any runtime dependencies:

```powershell
python -m pip install -e .
```

## Run the tests

From this directory:

```powershell
python -m unittest discover -s tests -v
```

## Run the demonstration

```powershell
python examples/demo.py
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

result = verify_qr_image("ticket.png", public_key)
print(result.status)   # VerifyStatus.VALID
```

Verification checks, in order: the payload format, the RSA-PSS signature, the
ticket fields, and that today is not past the valid-until date (inclusive).
Possible results: `VALID`, `BAD_FORMAT`, `BAD_SIGNATURE`, `EXPIRED`,
`UNREADABLE_QR`.

Limitation: verification is fully offline, so a photographed or copied QR code
passes as many times as it is scanned. Catching reuse needs a shared list of
used ticket ids, which this project does not include.

Run the demo with `python examples/qr_demo.py`.
