from datetime import date
import json
from pathlib import Path
import sys
import tempfile
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto import generate_key_pair
from qrticket import (
    EventProfile,
    load_event_profile,
    public_key_fingerprint,
    save_event_profile,
)


class EventProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, _ = generate_key_pair(bits=1024, primality_rounds=24)

    def make_profile(self, **changes) -> EventProfile:
        values = {
            "event": "EVENT 2027",
            "valid_until": date(2027, 12, 31),
            "batch_id": "BATCH-01",
            "public_key_file": "public-key.json",
            "public_key_fingerprint": public_key_fingerprint(self.public_key),
        }
        values.update(changes)
        return EventProfile(**values)

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            profile = self.make_profile()
            save_event_profile(profile, path)
            self.assertEqual(load_event_profile(path), profile)

    def test_rejects_public_key_path_escape(self) -> None:
        with self.assertRaises(ValueError):
            self.make_profile(public_key_file="../private-key.json")

    def test_rejects_bad_fingerprint(self) -> None:
        with self.assertRaises(ValueError):
            self.make_profile(public_key_fingerprint="not-a-fingerprint")

    def test_rejects_unknown_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(
                json.dumps(
                    {
                        "format": "unknown",
                        "version": 1,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_event_profile(path)


if __name__ == "__main__":
    unittest.main()
