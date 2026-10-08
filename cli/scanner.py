import argparse
from collections import Counter
from collections.abc import Callable
import csv
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from crypto import RSAPublicKey, load_public_key
from qrticket import (
    EventProfile,
    TicketFormatError,
    VerificationResult,
    VerifyStatus,
    load_event_profile,
    public_key_fingerprint,
    verify_payload,
)
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
    audit_log_path: Path | None = None

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


def _load_scanner_profile(
    path: str | Path,
) -> tuple[EventProfile, Path, RSAPublicKey]:
    profile_path = Path(path)
    profile = load_event_profile(profile_path)
    key_path = profile_path.parent / profile.public_key_file
    public_key = load_public_key(key_path)
    fingerprint = public_key_fingerprint(public_key)
    if fingerprint != profile.public_key_fingerprint:
        raise CameraScannerError("event profile does not match its public key")
    return profile, key_path, public_key


def _prompt_profile(
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> tuple[Path, EventProfile, Path, RSAPublicKey]:
    while True:
        value = _prompt_required("Event profile file: ", input_fn, output_fn)
        profile_path = Path(value.strip('"\''))
        try:
            profile, key_path, public_key = _load_scanner_profile(profile_path)
            return profile_path, profile, key_path, public_key
        except (OSError, TypeError, ValueError, CameraScannerError) as error:
            output_fn(f"Could not load event profile: {error}")


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
    if summary.audit_log_path is not None:
        output_fn(f"Audit log: {summary.audit_log_path}")


def _write_audit_record(
    path: Path,
    scanner_id: str,
    result: VerificationResult,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists() or path.stat().st_size == 0
    ticket = result.ticket

    with path.open("a", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=(
                "timestamp",
                "scanner_id",
                "status",
                "ticket_id",
                "event",
                "ticket_type",
                "valid_until",
            ),
        )
        if write_header:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                "scanner_id": scanner_id,
                "status": result.status.value,
                "ticket_id": ticket.ticket_id if ticket is not None else "",
                "event": ticket.event if ticket is not None else "",
                "ticket_type": ticket.category if ticket is not None else "",
                "valid_until": (
                    ticket.valid_until.isoformat() if ticket is not None else ""
                ),
            }
        )


def scan_camera(
    public_key: RSAPublicKey,
    expected_event: str,
    camera_index: int = 0,
    today: date | None = None,
    audit_log_path: str | Path | None = None,
    scanner_id: str = "CAMERA-0",
    cv2_module: Any | None = None,
    decode_frame: DecodeFunction | None = None,
    output_fn: OutputFunction | None = None,
) -> CameraScanSummary:
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("public_key must be an RSAPublicKey")
    if not isinstance(expected_event, str) or not expected_event:
        raise TypeError("expected_event must be a non-empty string")
    try:
        Ticket("VALIDATION", expected_event, date.max, "VALIDATION")
        Ticket("VALIDATION", "VALIDATION", date.max, scanner_id)
    except TicketFormatError as error:
        raise ValueError(str(error)) from error
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
    audit_path = Path(audit_log_path) if audit_log_path is not None else None

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
                    if audit_path is not None:
                        _write_audit_record(audit_path, scanner_id, current_result)

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

    summary = CameraScanSummary(dict(counts), audit_path)
    _print_summary(summary, output_fn)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify RSA-signed QR tickets with a camera"
    )
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--event")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--camera", type=int, default=0)
    parser.add_argument("--date")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--scanner-id")
    arguments = parser.parse_args(argv)

    _print_banner(print)
    try:
        if arguments.profile is not None:
            if arguments.public_key is not None or arguments.event is not None:
                raise CameraScannerError(
                    "use either --profile or --public-key with --event"
                )
            profile_path = arguments.profile
            profile, key_path, public_key = _load_scanner_profile(profile_path)
            event = profile.event
            default_log = profile_path.parent / "scan-log.csv"
        elif arguments.public_key is not None or arguments.event is not None:
            if arguments.public_key is None or arguments.event is None:
                raise CameraScannerError(
                    "manual setup requires both --public-key and --event"
                )
            profile = None
            key_path = arguments.public_key
            public_key = load_public_key(key_path)
            event = arguments.event
            default_log = Path("scan-log.csv")
        else:
            profile_path, profile, key_path, public_key = _prompt_profile(input, print)
            event = profile.event
            default_log = profile_path.parent / "scan-log.csv"

        scan_date = _parse_date(arguments.date)
        audit_log_path = arguments.log or default_log
        scanner_id = arguments.scanner_id or f"CAMERA-{arguments.camera}"
        print(f"Public key: {key_path}")
        print(f"Expected event: {event}")
        if profile is not None:
            print(f"Batch ID: {profile.batch_id}")
            print(f"Tickets valid until: {profile.valid_until.isoformat()}")
        print(f"Scan date: {scan_date.isoformat()}")
        print(f"Scanner ID: {scanner_id}")
        print(f"Audit log: {audit_log_path}")
        scan_camera(
            public_key=public_key,
            expected_event=event,
            camera_index=arguments.camera,
            today=scan_date,
            audit_log_path=audit_log_path,
            scanner_id=scanner_id,
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
