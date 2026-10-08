from pathlib import Path
import subprocess
import sys
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"


class ImportTests(unittest.TestCase):
    def test_core_ticket_api_does_not_import_qr_libraries(self) -> None:
        script = f"""
import builtins
import sys
sys.path.insert(0, {str(SOURCE_DIRECTORY)!r})
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.partition('.')[0] in {{'PIL', 'segno', 'zxingcpp'}}:
        raise AssertionError(f'unexpected QR dependency: {{name}}')
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
from qrticket import Ticket, issue_ticket, verify_payload
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
