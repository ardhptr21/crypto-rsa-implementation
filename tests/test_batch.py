import csv
from datetime import date
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto import generate_key_pair, load_public_key
from qrticket import (
    TicketType,
    VerifyStatus,
    issue_ticket_batch,
    load_event_profile,
    public_key_fingerprint,
    verify_qr_image,
)


class BatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, cls.private_key = generate_key_pair(
            bits=1024,
            primality_rounds=24,
        )

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)

    def test_generates_mixed_ticket_types_and_manifest(self) -> None:
        destination = self.directory / "event-2027"
        progress: list[tuple[int, int, str]] = []
        result = issue_ticket_batch(
            event="EVENT 2027",
            valid_until=date(2027, 12, 31),
            ticket_types=(TicketType("STANDARD", 2), TicketType("GOLD", 1)),
            private_key=self.private_key,
            output_directory=destination,
            batch_id="BATCH-01",
            progress=lambda completed, total, ticket: progress.append(
                (completed, total, ticket.ticket_id)
            ),
        )

        self.assertEqual(result.total, 3)
        self.assertEqual([item[0] for item in progress], [1, 2, 3])
        self.assertTrue(all(item[1] == 3 for item in progress))
        self.assertEqual(result.output_directory, destination)
        self.assertEqual(load_public_key(result.public_key_path), self.public_key)
        profile = load_event_profile(result.event_profile_path)
        self.assertEqual(profile.event, "EVENT 2027")
        self.assertEqual(profile.valid_until, date(2027, 12, 31))
        self.assertEqual(profile.batch_id, "BATCH-01")
        self.assertEqual(profile.public_key_file, "public-key.json")
        self.assertEqual(
            profile.public_key_fingerprint,
            public_key_fingerprint(self.public_key),
        )
        self.assertEqual(
            [ticket.ticket_id for ticket in result.tickets],
            [
                "EVENT-2027-STANDARD-BATCH-01-0001",
                "EVENT-2027-STANDARD-BATCH-01-0002",
                "EVENT-2027-GOLD-BATCH-01-0001",
            ],
        )

        with result.manifest_path.open(encoding="utf-8", newline="") as file:
            rows = list(csv.DictReader(file))
        self.assertEqual(len(rows), 3)
        self.assertEqual(result.batch_id, "BATCH-01")
        self.assertEqual(rows[0]["batch_id"], "BATCH-01")
        self.assertEqual(rows[0]["ticket_type"], "STANDARD")
        self.assertEqual(rows[2]["ticket_type"], "GOLD")

        for row in rows:
            qr_path = destination / row["qr_file"]
            verification = verify_qr_image(
                qr_path,
                self.public_key,
                today=date(2027, 1, 1),
                expected_event="EVENT 2027",
            )
            self.assertEqual(verification.status, VerifyStatus.VALID)

    def test_refuses_to_overwrite_an_existing_directory(self) -> None:
        destination = self.directory / "existing"
        destination.mkdir()
        with self.assertRaises(FileExistsError):
            issue_ticket_batch(
                "EVENT",
                date(2027, 12, 31),
                (TicketType("STANDARD", 1),),
                self.private_key,
                destination,
            )

    def test_separate_batches_use_different_ticket_ids(self) -> None:
        first = issue_ticket_batch(
            "EVENT",
            date(2027, 12, 31),
            (TicketType("STANDARD", 1),),
            self.private_key,
            self.directory / "first",
        )
        second = issue_ticket_batch(
            "EVENT",
            date(2027, 12, 31),
            (TicketType("STANDARD", 1),),
            self.private_key,
            self.directory / "second",
        )
        self.assertNotEqual(first.batch_id, second.batch_id)
        self.assertNotEqual(first.tickets[0].ticket_id, second.tickets[0].ticket_id)

    def test_rejects_duplicate_or_colliding_ticket_types(self) -> None:
        for ticket_types in (
            (TicketType("GOLD", 1), TicketType("gold", 1)),
            (TicketType("V.I.P", 1), TicketType("V-I-P", 1)),
        ):
            with self.subTest(ticket_types=ticket_types):
                with self.assertRaises(ValueError):
                    issue_ticket_batch(
                        "EVENT",
                        date(2027, 12, 31),
                        ticket_types,
                        self.private_key,
                        self.directory / "output",
                    )

    def test_ticket_quantity_must_be_a_positive_integer(self) -> None:
        for quantity in (0, -1):
            with self.subTest(quantity=quantity):
                with self.assertRaises(ValueError):
                    TicketType("STANDARD", quantity)
        with self.assertRaises(TypeError):
            TicketType("STANDARD", True)

    def test_failure_does_not_publish_a_partial_batch(self) -> None:
        destination = self.directory / "failed"
        with patch(
            "qrticket.batch.issue_ticket_qr",
            side_effect=RuntimeError("render failed"),
        ):
            with self.assertRaises(RuntimeError):
                issue_ticket_batch(
                    "EVENT",
                    date(2027, 12, 31),
                    (TicketType("STANDARD", 2),),
                    self.private_key,
                    destination,
                )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
