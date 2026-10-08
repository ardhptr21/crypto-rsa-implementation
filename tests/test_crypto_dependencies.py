import ast
from pathlib import Path
import subprocess
import sys
import unittest


PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORY = PROJECT_DIRECTORY / "src"
CRYPTO_DIRECTORY = SOURCE_DIRECTORY / "crypto"


class CryptoDependencyTests(unittest.TestCase):
    def test_crypto_imports_only_standard_library_or_local_modules(self) -> None:
        standard_library = sys.stdlib_module_names

        for path in CRYPTO_DIRECTORY.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module = alias.name.partition(".")[0]
                        self.assertIn(module, standard_library, f"{path}: {module}")
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    module = (node.module or "").partition(".")[0]
                    self.assertIn(module, standard_library, f"{path}: {module}")

    def test_crypto_imports_without_site_packages(self) -> None:
        script = f"""
import sys
sys.path.insert(0, {str(SOURCE_DIRECTORY)!r})
from crypto import generate_key_pair, sign_pss, verify_pss
public_key, private_key = generate_key_pair(bits=1024, primality_rounds=8)
message = b'standard-library-only'
signature = sign_pss(message, private_key)
assert verify_pss(message, signature, public_key)
"""
        completed = subprocess.run(
            [sys.executable, "-S", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
