from pathlib import Path
import sys


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto import (
    decrypt_oaep,
    encrypt_oaep,
    generate_key_pair,
    sign_pss,
    verify_pss,
)


def main() -> None:
    print("Generating a 2048-bit RSA key pair...")
    public_key, private_key = generate_key_pair()

    secret = b"Short provisioning secret"
    ciphertext = encrypt_oaep(secret, public_key)
    recovered = decrypt_oaep(ciphertext, private_key)

    ticket = b"V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT"
    signature = sign_pss(ticket, private_key)

    print(f"Key size: {public_key.n.bit_length()} bits")
    print(f"OAEP round trip: {recovered == secret}")
    print(f"Ticket signature valid: {verify_pss(ticket, signature, public_key)}")
    print(
        "Changed ticket valid: "
        f"{verify_pss(ticket + b'-VIP', signature, public_key)}"
    )


if __name__ == "__main__":
    main()
