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
