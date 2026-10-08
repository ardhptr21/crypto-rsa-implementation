from datetime import date
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORY = PROJECT_DIRECTORY / "src"
if str(PROJECT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIRECTORY))
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from cli.scanner import CameraScannerError, _default_decoder, scan_camera
from crypto import generate_key_pair
from qrticket import Ticket, VerifyStatus, issue_ticket, issue_ticket_qr


class FakeCapture:
    def __init__(self, opened: bool = True) -> None:
        self.opened = opened
        self.released = False

    def isOpened(self) -> bool:
        return self.opened

    def read(self):
        return True, object()

    def release(self) -> None:
        self.released = True


class FakeCV2:
    FONT_HERSHEY_SIMPLEX = 0
    LINE_AA = 0

    def __init__(self, keys: list[int], opened: bool = True) -> None:
        self.capture = FakeCapture(opened)
        self.keys = iter(keys)
        self.destroyed = False
        self.frames_shown = 0

    def VideoCapture(self, camera_index: int) -> FakeCapture:
        return self.capture

    def putText(self, *args, **kwargs) -> None:
        return None

    def imshow(self, name: str, frame) -> None:
        self.frames_shown += 1

    def waitKey(self, delay: int) -> int:
        return next(self.keys)

    def destroyAllWindows(self) -> None:
        self.destroyed = True


class CameraScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, cls.private_key = generate_key_pair(
            bits=1024,
            primality_rounds=24,
        )
        cls.ticket = Ticket(
            "CAMERA-0001",
            "CAMERA EVENT",
            date(2027, 12, 31),
            "VIP",
        )
        cls.payload = issue_ticket(cls.ticket, cls.private_key)

    def test_camera_scans_and_verifies_a_valid_ticket(self) -> None:
        cv2_module = FakeCV2([ord("q")])
        messages: list[str] = []

        summary = scan_camera(
            public_key=self.public_key,
            expected_event="CAMERA EVENT",
            today=date(2027, 1, 1),
            cv2_module=cv2_module,
            decode_frame=lambda frame: [self.payload],
            output_fn=messages.append,
        )

        self.assertEqual(summary.total, 1)
        self.assertEqual(summary.counts[VerifyStatus.VALID], 1)
        self.assertTrue(cv2_module.capture.released)
        self.assertTrue(cv2_module.destroyed)
        self.assertIn("[VALID TICKET]", messages)
        self.assertIn("Ticket ID: CAMERA-0001", messages)

    def test_decoder_reads_a_generated_qr_as_an_opencv_frame(self) -> None:
        import cv2

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ticket.png"
            payload = issue_ticket_qr(self.ticket, self.private_key, path)
            frame = cv2.imread(str(path))
            self.assertIsNotNone(frame)
            self.assertEqual(_default_decoder(frame), [payload])

    def test_visible_ticket_is_counted_only_once(self) -> None:
        cv2_module = FakeCV2([0, 0, ord("q")])
        summary = scan_camera(
            public_key=self.public_key,
            expected_event="CAMERA EVENT",
            today=date(2027, 1, 1),
            cv2_module=cv2_module,
            decode_frame=lambda frame: [self.payload],
            output_fn=lambda message: None,
        )
        self.assertEqual(summary.total, 1)

    def test_wrong_event_is_reported(self) -> None:
        cv2_module = FakeCV2([ord("q")])
        summary = scan_camera(
            public_key=self.public_key,
            expected_event="OTHER EVENT",
            today=date(2027, 1, 1),
            cv2_module=cv2_module,
            decode_frame=lambda frame: [self.payload],
            output_fn=lambda message: None,
        )
        self.assertEqual(summary.counts[VerifyStatus.WRONG_EVENT], 1)

    def test_multiple_qr_codes_are_not_verified(self) -> None:
        cv2_module = FakeCV2([ord("q")])
        summary = scan_camera(
            public_key=self.public_key,
            expected_event="CAMERA EVENT",
            today=date(2027, 1, 1),
            cv2_module=cv2_module,
            decode_frame=lambda frame: [self.payload, self.payload],
            output_fn=lambda message: None,
        )
        self.assertEqual(summary.total, 0)

    def test_unavailable_camera_raises(self) -> None:
        cv2_module = FakeCV2([], opened=False)
        with self.assertRaises(CameraScannerError):
            scan_camera(
                public_key=self.public_key,
                expected_event="CAMERA EVENT",
                cv2_module=cv2_module,
                decode_frame=lambda frame: [],
                output_fn=lambda message: None,
            )
        self.assertTrue(cv2_module.capture.released)


if __name__ == "__main__":
    unittest.main()
