from pathlib import Path
import sys
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from qrticket.errors import PayloadFormatError
from qrticket.payload import MAX_PAYLOAD_LENGTH, PREFIX, decode_payload, encode_payload


TICKET = b"V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT"
SIGNATURE = bytes(range(256))


class PayloadTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        text = encode_payload(TICKET, SIGNATURE)
        self.assertTrue(text.startswith(PREFIX + "."))
        self.assertEqual(decode_payload(text), (TICKET, SIGNATURE))

    def test_uses_unpadded_url_safe_alphabet(self) -> None:
        text = encode_payload(b"\xfb\xff\xfe", b"\xff\xff")
        self.assertNotIn("=", text)
        self.assertNotIn("+", text)
        self.assertNotIn("/", text)

    def test_rejects_wrong_prefix_and_part_count(self) -> None:
        good = encode_payload(TICKET, SIGNATURE)
        _, ticket_part, signature_part = good.split(".")
        for text in (
            "RQT2." + ticket_part + "." + signature_part,
            ticket_part + "." + signature_part,
            good + ".extra",
            "RQT1." + ticket_part,
            "",
            "RQT1..",
        ):
            with self.subTest(text=text[:30]):
                with self.assertRaises(PayloadFormatError):
                    decode_payload(text)

    def test_rejects_padding_bad_characters_and_whitespace(self) -> None:
        good = encode_payload(TICKET, SIGNATURE)
        for text in (
            good + "=",
            good + "\n",
            " " + good,
            good.replace("RQT1.", "RQT1.!"),
            good[:-1] + "+",
        ):
            with self.subTest(text=text[-12:]):
                with self.assertRaises(PayloadFormatError):
                    decode_payload(text)

    def test_rejects_non_canonical_base64(self) -> None:
        with self.assertRaises(PayloadFormatError):
            decode_payload("RQT1.QR.QQ")

    def test_rejects_impossible_base64_length(self) -> None:
        with self.assertRaises(PayloadFormatError):
            decode_payload("RQT1.Q.QQ")

    def test_encode_rejects_empty_parts(self) -> None:
        with self.assertRaises(PayloadFormatError):
            encode_payload(b"", SIGNATURE)
        with self.assertRaises(PayloadFormatError):
            encode_payload(TICKET, b"")

    def test_rejects_payloads_over_the_limit(self) -> None:
        oversized = "RQT1." + "A" * MAX_PAYLOAD_LENGTH + ".QQ"
        with self.assertRaises(PayloadFormatError):
            decode_payload(oversized)
        with self.assertRaises(PayloadFormatError):
            encode_payload(b"A" * MAX_PAYLOAD_LENGTH, SIGNATURE)

    def test_type_errors(self) -> None:
        with self.assertRaises(TypeError):
            encode_payload("text", SIGNATURE)
        with self.assertRaises(TypeError):
            decode_payload(b"RQT1.a.b")


if __name__ == "__main__":
    unittest.main()
