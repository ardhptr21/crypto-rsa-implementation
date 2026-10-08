from datetime import date, datetime, timedelta
from pathlib import Path
import sys
import tempfile
import unittest

from PIL import Image


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto import generate_key_pair, sign_pss
from qrticket import (
    Ticket,
    VerifyStatus,
    issue_ticket,
    issue_ticket_qr,
    verify_payload,
    verify_qr_image,
)
from qrticket.payload import decode_payload, encode_payload


VALID_UNTIL = date(2026, 12, 31)


def make_ticket(ticket_id: str = "TKT-0001") -> Ticket:
    return Ticket(ticket_id, "EVENT-2026", VALID_UNTIL, "STUDENT")


class IssueVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, cls.private_key = generate_key_pair(
            bits=1024, primality_rounds=24
        )
        cls.other_public_key, _ = generate_key_pair(bits=1024, primality_rounds=24)

    def issue(self, ticket: Ticket | None = None) -> str:
        return issue_ticket(ticket or make_ticket(), self.private_key)

    def test_valid_ticket(self) -> None:
        result = verify_payload(self.issue(), self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.VALID)
        self.assertTrue(result.valid)
        self.assertEqual(result.ticket, make_ticket())

    def test_expiry_boundary_is_inclusive(self) -> None:
        payload = self.issue()
        last_day = verify_payload(payload, self.public_key, today=VALID_UNTIL)
        next_day = verify_payload(
            payload, self.public_key, today=VALID_UNTIL + timedelta(days=1)
        )
        self.assertEqual(last_day.status, VerifyStatus.VALID)
        self.assertEqual(next_day.status, VerifyStatus.EXPIRED)
        self.assertFalse(next_day.valid)
        self.assertEqual(next_day.ticket, make_ticket())

    def test_today_defaults_to_the_local_date(self) -> None:
        expired = issue_ticket(
            Ticket("TKT-0002", "EVENT-2026", date(2000, 1, 1), "STUDENT"),
            self.private_key,
        )
        self.assertEqual(
            verify_payload(expired, self.public_key).status, VerifyStatus.EXPIRED
        )

    def test_today_must_be_a_date(self) -> None:
        with self.assertRaises(TypeError):
            verify_payload(self.issue(), self.public_key, today=datetime(2026, 6, 1))
        with self.assertRaises(TypeError):
            verify_payload(self.issue(), self.public_key, today="2026-06-01")

    def test_ticket_can_be_bound_to_the_expected_event(self) -> None:
        payload = self.issue()
        matching = verify_payload(
            payload,
            self.public_key,
            today=date(2026, 6, 1),
            expected_event="EVENT-2026",
        )
        other = verify_payload(
            payload,
            self.public_key,
            today=date(2026, 6, 1),
            expected_event="OTHER-EVENT",
        )
        self.assertEqual(matching.status, VerifyStatus.VALID)
        self.assertEqual(other.status, VerifyStatus.WRONG_EVENT)
        self.assertEqual(other.ticket, make_ticket())

    def test_expected_event_must_be_a_string(self) -> None:
        with self.assertRaises(TypeError):
            verify_payload(
                self.issue(),
                self.public_key,
                expected_event=2026,
            )

    def test_tampered_ticket_is_bad_signature(self) -> None:
        ticket_bytes, signature = decode_payload(self.issue())
        tampered = ticket_bytes.replace(b"STUDENT", b"VIP-ACC")
        payload = encode_payload(tampered, signature)
        result = verify_payload(payload, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_SIGNATURE)
        self.assertIsNone(result.ticket)

    def test_tampered_signature_is_bad_signature(self) -> None:
        ticket_bytes, signature = decode_payload(self.issue())
        flipped = bytearray(signature)
        flipped[10] ^= 1
        payload = encode_payload(ticket_bytes, bytes(flipped))
        result = verify_payload(payload, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_SIGNATURE)

    def test_signature_swapped_between_two_valid_tickets(self) -> None:
        first_bytes, _ = decode_payload(self.issue(make_ticket("TKT-0001")))
        _, second_signature = decode_payload(self.issue(make_ticket("TKT-0002")))
        payload = encode_payload(first_bytes, second_signature)
        result = verify_payload(payload, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_SIGNATURE)

    def test_wrong_public_key_is_bad_signature(self) -> None:
        result = verify_payload(
            self.issue(), self.other_public_key, today=date(2026, 6, 1)
        )
        self.assertEqual(result.status, VerifyStatus.BAD_SIGNATURE)

    def test_garbage_text_is_bad_format(self) -> None:
        for text in ("", "hello", "RQT1.a.b", "RQT1.QQ.QQ.QQ"):
            with self.subTest(text=text):
                result = verify_payload(text, self.public_key, today=date(2026, 6, 1))
                self.assertEqual(result.status, VerifyStatus.BAD_FORMAT)

    def test_trailing_newline_from_a_scanner_is_bad_format(self) -> None:
        result = verify_payload(
            self.issue() + "\n", self.public_key, today=date(2026, 6, 1)
        )
        self.assertEqual(result.status, VerifyStatus.BAD_FORMAT)

    def test_huge_garbage_is_rejected(self) -> None:
        text = "RQT1." + "A" * 1_000_000 + ".AAAA"
        result = verify_payload(text, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_FORMAT)

    def test_valid_signature_over_a_malformed_ticket_is_bad_format(self) -> None:
        ticket_bytes = b"V1|only|three|fields"
        signature = sign_pss(ticket_bytes, self.private_key)
        payload = encode_payload(ticket_bytes, signature)
        result = verify_payload(payload, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_FORMAT)
        self.assertIsNone(result.ticket)

    def test_signature_is_checked_before_the_ticket_is_parsed(self) -> None:
        payload = encode_payload(b"garbage", b"\x01" * 128)
        result = verify_payload(payload, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_SIGNATURE)
        self.assertIsNone(result.ticket)

    def test_forged_expired_ticket_is_bad_signature_not_expired(self) -> None:
        payload = encode_payload(b"V1|X|E|2000-01-01|C", b"\x01" * 128)
        result = verify_payload(payload, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.BAD_SIGNATURE)
        self.assertIsNone(result.ticket)

    def test_issue_requires_a_ticket(self) -> None:
        with self.assertRaises(TypeError):
            issue_ticket(b"V1|a|b|2026-12-31|c", self.private_key)


class ImageRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, cls.private_key = generate_key_pair(
            bits=1024, primality_rounds=24
        )

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)

    def test_png_round_trip_is_valid(self) -> None:
        path = self.directory / "ticket.png"
        payload = issue_ticket_qr(make_ticket(), self.private_key, path)
        self.assertTrue(payload.startswith("RQT1."))
        result = verify_qr_image(path, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.VALID)
        self.assertEqual(result.ticket, make_ticket())

    def test_png_is_bound_to_the_expected_event(self) -> None:
        path = self.directory / "ticket.png"
        issue_ticket_qr(make_ticket(), self.private_key, path)
        result = verify_qr_image(
            path,
            self.public_key,
            today=date(2026, 6, 1),
            expected_event="OTHER-EVENT",
        )
        self.assertEqual(result.status, VerifyStatus.WRONG_EVENT)

    def test_expired_ticket_in_a_png(self) -> None:
        path = self.directory / "ticket.png"
        issue_ticket_qr(make_ticket(), self.private_key, path)
        result = verify_qr_image(path, self.public_key, today=date(2027, 1, 1))
        self.assertEqual(result.status, VerifyStatus.EXPIRED)

    def test_unreadable_images_are_reported(self) -> None:
        blank = self.directory / "blank.png"
        Image.new("L", (200, 200), 255).save(blank)
        junk = self.directory / "junk.png"
        junk.write_bytes(b"not an image")
        for path in (blank, junk, self.directory / "missing.png"):
            with self.subTest(path=path.name):
                result = verify_qr_image(path, self.public_key, today=date(2026, 6, 1))
                self.assertEqual(result.status, VerifyStatus.UNREADABLE_QR)
                self.assertIsNone(result.ticket)

    def test_two_qr_codes_in_one_image_are_unreadable(self) -> None:
        single_path = self.directory / "one.png"
        issue_ticket_qr(make_ticket(), self.private_key, single_path)
        with Image.open(single_path) as one:
            single = one.convert("L")
        width, height = single.size
        both = Image.new("L", (width * 2, height), 255)
        both.paste(single, (0, 0))
        both.paste(single, (width, 0))
        both_path = self.directory / "two.png"
        both.save(both_path)
        result = verify_qr_image(both_path, self.public_key, today=date(2026, 6, 1))
        self.assertEqual(result.status, VerifyStatus.UNREADABLE_QR)


if __name__ == "__main__":
    unittest.main()
