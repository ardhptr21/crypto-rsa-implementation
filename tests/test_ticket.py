from datetime import date, datetime
from pathlib import Path
import sys
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from qrticket.errors import TicketFormatError
from qrticket.ticket import Ticket, parse_ticket


SAMPLE = b"V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT"


class TicketTests(unittest.TestCase):
    def make(self, **overrides) -> Ticket:
        fields = dict(
            ticket_id="TKT-0001",
            event="EVENT-2026",
            valid_until=date(2026, 12, 31),
            category="STUDENT",
        )
        fields.update(overrides)
        return Ticket(**fields)

    def test_to_bytes_matches_readme_sample(self) -> None:
        self.assertEqual(self.make().to_bytes(), SAMPLE)

    def test_round_trip(self) -> None:
        self.assertEqual(parse_ticket(SAMPLE), self.make())

    def test_rejects_wrong_version(self) -> None:
        with self.assertRaises(TicketFormatError):
            parse_ticket(b"V2|TKT-0001|EVENT-2026|2026-12-31|STUDENT")

    def test_rejects_wrong_field_count(self) -> None:
        for data in (
            b"V1|TKT-0001|EVENT-2026|2026-12-31",
            b"V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT|EXTRA",
            b"",
        ):
            with self.subTest(data=data):
                with self.assertRaises(TicketFormatError):
                    parse_ticket(data)

    def test_rejects_empty_field(self) -> None:
        with self.assertRaises(TicketFormatError):
            parse_ticket(b"V1||EVENT-2026|2026-12-31|STUDENT")

    def test_rejects_separator_inside_a_field(self) -> None:
        with self.assertRaises(TicketFormatError):
            self.make(ticket_id="A|B")

    def test_rejects_non_ascii_and_control_characters(self) -> None:
        with self.assertRaises(TicketFormatError):
            self.make(event="EVéNT")
        with self.assertRaises(TicketFormatError):
            self.make(category="STU\nDENT")
        with self.assertRaises(TicketFormatError):
            parse_ticket("V1|TKT|EVéNT|2026-12-31|STUDENT".encode("utf-8"))

    def test_rejects_impossible_and_oddly_formatted_dates(self) -> None:
        for text in (
            b"2026-02-30",
            b"31-12-2026",
            b"20261231",
            b"2026-1-5",
            b"0000-01-01",
        ):
            with self.subTest(text=text):
                with self.assertRaises(TicketFormatError):
                    parse_ticket(b"V1|TKT-0001|EVENT-2026|" + text + b"|STUDENT")

    def test_rejects_datetime_as_valid_until(self) -> None:
        with self.assertRaises(TicketFormatError):
            self.make(valid_until=datetime(2026, 12, 31, 12, 0))

    def test_parse_requires_bytes(self) -> None:
        with self.assertRaises(TypeError):
            parse_ticket("V1|TKT-0001|EVENT-2026|2026-12-31|STUDENT")


if __name__ == "__main__":
    unittest.main()
