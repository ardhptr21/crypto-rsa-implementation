from datetime import date, timedelta
from pathlib import Path
import sys
import tempfile
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from cli.main import _collect_ticket_types, run_interactive


class CLITests(unittest.TestCase):
    def test_collects_dynamic_ticket_types(self) -> None:
        answers = iter(("BACKSTAGE", "2", "y", "PRESS", "3", "n"))
        messages: list[str] = []
        ticket_types = _collect_ticket_types(
            lambda prompt: next(answers),
            messages.append,
        )
        self.assertEqual(len(ticket_types), 2)
        self.assertEqual(ticket_types[0].name, "BACKSTAGE")
        self.assertEqual(ticket_types[0].quantity, 2)
        self.assertEqual(ticket_types[1].name, "PRESS")
        self.assertEqual(ticket_types[1].quantity, 3)

    def test_interactive_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_directory = root / "tickets"
            private_key_path = root / "keys" / "event.private.json"
            valid_until = date.today() + timedelta(days=365)
            answers = iter(
                (
                    "University Expo",
                    valid_until.isoformat(),
                    str(output_directory),
                    str(private_key_path),
                    "STANDARD",
                    "2",
                    "y",
                    "GOLD",
                    "1",
                    "n",
                    "y",
                )
            )
            messages: list[str] = []

            status = run_interactive(
                key_bits=1024,
                input_fn=lambda prompt: next(answers),
                output_fn=messages.append,
            )

            self.assertEqual(status, 0)
            self.assertTrue(private_key_path.exists())
            self.assertTrue((root / "keys" / "event.public.json").exists())
            self.assertTrue((output_directory / "manifest.csv").exists())
            self.assertTrue((output_directory / "public-key.json").exists())
            self.assertEqual(len(list((output_directory / "qr").glob("*.png"))), 3)
            self.assertIn("Generated tickets: 3", messages)


if __name__ == "__main__":
    unittest.main()
