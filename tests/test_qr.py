from pathlib import Path
import sys
import tempfile
import unittest

from PIL import Image


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from qrticket.errors import QRReadError
from qrticket.qr import read_qr, render_qr


TEXT = "RQT1." + "Ab_-" * 100


class QRTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)

    def test_render_then_read_round_trip(self) -> None:
        path = self.directory / "ticket.png"
        render_qr(TEXT, path)
        self.assertTrue(path.exists())
        self.assertEqual(read_qr(path), TEXT)

    def test_round_trip_at_other_scales_and_levels(self) -> None:
        for scale, error in ((4, "l"), (10, "q")):
            with self.subTest(scale=scale, error=error):
                path = self.directory / f"t_{scale}_{error}.png"
                render_qr(TEXT, path, scale=scale, error=error)
                self.assertEqual(read_qr(path), TEXT)

    def test_reads_an_rgb_copy_of_the_image(self) -> None:
        path = self.directory / "ticket.png"
        render_qr(TEXT, path)
        rgb_path = self.directory / "ticket_rgb.png"
        with Image.open(path) as image:
            image.convert("RGB").save(rgb_path)
        self.assertEqual(read_qr(rgb_path), TEXT)

    def test_blank_image_raises(self) -> None:
        path = self.directory / "blank.png"
        Image.new("L", (200, 200), 255).save(path)
        with self.assertRaises(QRReadError):
            read_qr(path)

    def test_two_qr_codes_in_one_image_raises(self) -> None:
        path = self.directory / "one.png"
        render_qr(TEXT, path)
        with Image.open(path) as one:
            single = one.convert("L")
        width, height = single.size
        both = Image.new("L", (width * 2, height), 255)
        both.paste(single, (0, 0))
        both.paste(single, (width, 0))
        both_path = self.directory / "two.png"
        both.save(both_path)
        with self.assertRaises(QRReadError):
            read_qr(both_path)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(QRReadError):
            read_qr(self.directory / "does_not_exist.png")

    def test_non_image_file_raises(self) -> None:
        path = self.directory / "junk.png"
        path.write_bytes(b"this is not an image")
        with self.assertRaises(QRReadError):
            read_qr(path)

    def test_render_requires_text(self) -> None:
        with self.assertRaises(TypeError):
            render_qr(b"bytes", self.directory / "x.png")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
