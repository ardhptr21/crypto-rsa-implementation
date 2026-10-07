from pathlib import Path

from PIL import Image
import segno
import zxingcpp

from .errors import QRReadError


def render_qr(
    text: str,
    path: str | Path,
    scale: int = 8,
    border: int = 4,
    error: str = "m",
) -> None:
    if not isinstance(text, str):
        raise TypeError("QR text must be a string")
    code = segno.make_qr(text, error=error, boost_error=False)
    code.save(str(path), kind="png", scale=scale, border=border)


def read_qr(path: str | Path) -> str:
    try:
        with Image.open(path) as image:
            grayscale = image.convert("L")
    except (OSError, Image.DecompressionBombError) as error:
        raise QRReadError("could not open the image") from error

    codes = zxingcpp.read_barcodes(
        grayscale, formats=zxingcpp.BarcodeFormat.QRCode
    )
    if not codes:
        raise QRReadError("no QR code found in the image")
    if len(codes) > 1:
        raise QRReadError("the image contains more than one QR code")
    return codes[0].text
