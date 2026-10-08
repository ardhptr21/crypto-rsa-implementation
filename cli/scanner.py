import argparse
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from crypto import RSAPublicKey, load_public_key
from qrticket import VerificationResult, VerifyStatus, verify_payload
from qrticket.batch import slugify
from qrticket.ticket import Ticket


InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]
DecodeFunction = Callable[[Any], list[str]]
SCREEN_WIDTH = 62
WINDOW_NAME = "RSA QR Ticket Scanner"


class CameraScannerError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class CameraScanSummary:
    counts: dict[VerifyStatus, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _print_banner(output_fn: OutputFunction) -> None:
    output_fn("=" * SCREEN_WIDTH)
    output_fn("RSA QR TICKET CAMERA SCANNER".center(SCREEN_WIDTH))
    output_fn("Verify signed tickets using a live camera".center(SCREEN_WIDTH))
    output_fn("=" * SCREEN_WIDTH)


def _prompt_required(
    prompt: str,
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> str:
    while True:
        value = input_fn(prompt).strip()
        if value:
            return value
        output_fn("A value is required.")


def _prompt_public_key(
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> tuple[Path, RSAPublicKey]:
    while True:
        value = _prompt_required("Public key file: ", input_fn, output_fn)
        path = Path(value.strip('"\''))
        try:
            return path, load_public_key(path)
        except (OSError, TypeError, ValueError) as error:
            output_fn(f"Could not load public key: {error}")


def _prompt_event(input_fn: InputFunction, output_fn: OutputFunction) -> str:
    while True:
        event = _prompt_required("Expected event name or ID: ", input_fn, output_fn)
        try:
            Ticket("VALIDATION", event, date.max, "VALIDATION")
            slugify(event)
        except (TypeError, ValueError) as error:
            output_fn(f"Invalid event: {error}")
            continue
        return event


def _parse_date(value: str | None) -> date:
    if value is None:
        return date.today()
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise CameraScannerError("scan date must use YYYY-MM-DD format") from error


def _default_decoder(frame: Any) -> list[str]:
    import zxingcpp

    results = zxingcpp.read_barcodes(
        frame,
        formats=zxingcpp.BarcodeFormat.QRCode,
    )
    return [result.text for result in results if result.text]


def _status_label(result: VerificationResult) -> str:
    labels = {
        VerifyStatus.VALID: "VALID TICKET",
        VerifyStatus.BAD_FORMAT: "INVALID FORMAT",
        VerifyStatus.BAD_SIGNATURE: "INVALID SIGNATURE",
        VerifyStatus.WRONG_EVENT: "WRONG EVENT",
        VerifyStatus.EXPIRED: "EXPIRED TICKET",
        VerifyStatus.UNREADABLE_QR: "UNREADABLE QR",
    }
    return labels[result.status]


def _status_color(result: VerificationResult) -> tuple[int, int, int]:
    if result.status is VerifyStatus.VALID:
        return 0, 200, 0
    if result.status in {VerifyStatus.EXPIRED, VerifyStatus.WRONG_EVENT}:
        return 0, 165, 255
    return 0, 0, 255


def _print_result(
    result: VerificationResult,
    output_fn: OutputFunction,
) -> None:
    output_fn("")
    output_fn(f"[{_status_label(result)}]")
    if result.ticket is None:
        return
    output_fn(f"Ticket ID: {result.ticket.ticket_id}")
    output_fn(f"Event: {result.ticket.event}")
    output_fn(f"Ticket type: {result.ticket.category}")
    output_fn(f"Valid until: {result.ticket.valid_until.isoformat()}")


def _draw_overlay(
    cv2_module: Any,
    frame: Any,
    title: str,
    detail: str,
    color: tuple[int, int, int],
) -> None:
    cv2_module.putText(
        frame,
        title,
        (20, 35),
        cv2_module.FONT_HERSHEY_SIMPLEX,
        0.8,
        color,
        2,
        cv2_module.LINE_AA,
    )
    if detail:
        cv2_module.putText(
            frame,
            detail,
            (20, 70),
            cv2_module.FONT_HERSHEY_SIMPLEX,
            0.6,
            color,
            2,
            cv2_module.LINE_AA,
        )


def _print_summary(summary: CameraScanSummary, output_fn: OutputFunction) -> None:
    output_fn("")
    output_fn("=" * SCREEN_WIDTH)
    output_fn("SCAN SESSION SUMMARY".center(SCREEN_WIDTH))
    output_fn("=" * SCREEN_WIDTH)
    output_fn(f"Total scans: {summary.total}")
    for status in VerifyStatus:
        count = summary.counts.get(status, 0)
        if count:
            output_fn(f"{status.value}: {count}")


def scan_camera(
    public_key: RSAPublicKey,
    expected_event: str,
    camera_index: int = 0,
    today: date | None = None,
    cv2_module: Any | None = None,
    decode_frame: DecodeFunction | None = None,
    output_fn: OutputFunction | None = None,
) -> CameraScanSummary:
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("public_key must be an RSAPublicKey")
    if not isinstance(expected_event, str) or not expected_event:
        raise TypeError("expected_event must be a non-empty string")
    Ticket("VALIDATION", expected_event, date.max, "VALIDATION")
    if isinstance(camera_index, bool) or not isinstance(camera_index, int):
        raise TypeError("camera_index must be an integer")
    if camera_index < 0:
        raise ValueError("camera_index must not be negative")
    if today is None:
        today = date.today()
    elif type(today) is not date:
        raise TypeError("today must be a date")

    if cv2_module is None:
        try:
            import cv2 as cv2_module
        except ImportError as error:
            raise CameraScannerError(
                "OpenCV is required; install the project with the qr extra"
            ) from error
    decode_frame = _default_decoder if decode_frame is None else decode_frame
    output_fn = print if output_fn is None else output_fn

    capture = cv2_module.VideoCapture(camera_index)
    if not capture.isOpened():
        capture.release()
        raise CameraScannerError(f"could not open camera {camera_index}")

    counts: Counter[VerifyStatus] = Counter()
    active_payload: str | None = None
    missing_frames = 0
    current_result: VerificationResult | None = None
    overlay_title = "READY - SHOW A QR TICKET"
    overlay_detail = "Press Q or Esc to quit"
    overlay_color = (255, 255, 255)

    output_fn(f"Camera {camera_index} opened.")
    output_fn("Show one QR ticket at a time. Press Q or Esc to finish.")

    try:
        while True:
            success, frame = capture.read()
            if not success:
                raise CameraScannerError("camera stopped returning frames")

            payloads = decode_frame(frame)
            if not payloads:
                missing_frames += 1
                if missing_frames >= 10:
                    active_payload = None
                    current_result = None
                    overlay_title = "READY - SHOW A QR TICKET"
                    overlay_detail = "Press Q or Esc to quit"
                    overlay_color = (255, 255, 255)
            elif len(payloads) > 1:
                missing_frames = 0
                overlay_title = "MULTIPLE QR CODES"
                overlay_detail = "Show one ticket at a time"
                overlay_color = (0, 165, 255)
            else:
                missing_frames = 0
                payload = payloads[0]
                if payload != active_payload:
                    active_payload = payload
                    current_result = verify_payload(
                        payload,
                        public_key,
                        today=today,
                        expected_event=expected_event,
                    )
                    counts[current_result.status] += 1
                    _print_result(current_result, output_fn)

                if current_result is not None:
                    overlay_title = _status_label(current_result)
                    overlay_color = _status_color(current_result)
                    overlay_detail = (
                        current_result.ticket.ticket_id
                        if current_result.ticket is not None
                        else "Remove QR and try another ticket"
                    )

            _draw_overlay(
                cv2_module,
                frame,
                overlay_title,
                overlay_detail,
                overlay_color,
            )
            cv2_module.imshow(WINDOW_NAME, frame)
            key = cv2_module.waitKey(1) & 0xFF
            if key in (ord("q"), ord("Q"), 27):
                break
            if hasattr(cv2_module, "getWindowProperty"):
                visible = cv2_module.getWindowProperty(
                    WINDOW_NAME,
                    cv2_module.WND_PROP_VISIBLE,
                )
                if visible < 1:
                    break
    finally:
        capture.release()
        cv2_module.destroyAllWindows()

    summary = CameraScanSummary(dict(counts))
    _print_summary(summary, output_fn)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify RSA-signed QR tickets with a camera"
    )
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--event")
    parser.add_argument("--camera", type=int, default=0)
    parser.add_argument("--date")
    arguments = parser.parse_args(argv)

    _print_banner(print)
    try:
        if arguments.public_key is None:
            key_path, public_key = _prompt_public_key(input, print)
        else:
            key_path = arguments.public_key
            public_key = load_public_key(key_path)

        event = arguments.event or _prompt_event(input, print)
        scan_date = _parse_date(arguments.date)
        print(f"Public key: {key_path}")
        print(f"Expected event: {event}")
        print(f"Scan date: {scan_date.isoformat()}")
        scan_camera(
            public_key=public_key,
            expected_event=event,
            camera_index=arguments.camera,
            today=scan_date,
        )
        return 0
    except (OSError, TypeError, ValueError, CameraScannerError) as error:
        print(f"Scanner failed: {error}")
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nScanner stopped.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
