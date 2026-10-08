from datetime import date
from pathlib import Path
import sys
import tempfile


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto import generate_key_pair
from qrticket import Ticket, issue_ticket_qr, verify_qr_image
from qrticket.payload import decode_payload, encode_payload
from qrticket.qr import render_qr


def main() -> None:
    print("Generating a 2048-bit RSA key pair...")
    public_key, private_key = generate_key_pair()

    ticket = Ticket("TKT-0001", "EVENT-2026", date(2026, 12, 31), "STUDENT")

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ticket.png"
        payload = issue_ticket_qr(ticket, private_key, path)
        print(f"QR payload: {len(payload)} characters")

        result = verify_qr_image(
            path,
            public_key,
            today=date(2026, 6, 1),
            expected_event="EVENT-2026",
        )
        print(f"Genuine ticket:  {result.status.value} {result.ticket}")

        late = verify_qr_image(path, public_key, today=date(2027, 1, 1))
        print(f"After expiry:    {late.status.value}")

        ticket_bytes, signature = decode_payload(payload)
        forged = encode_payload(ticket_bytes.replace(b"STUDENT", b"VIP-ACC"), signature)
        forged_path = Path(directory) / "forged.png"
        render_qr(forged, forged_path)
        fake = verify_qr_image(forged_path, public_key, today=date(2026, 6, 1))
        print(f"Edited category: {fake.status.value}")


if __name__ == "__main__":
    main()
