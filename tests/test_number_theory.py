from pathlib import Path
import sys
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto.number_theory import (
    extended_gcd,
    gcd,
    modular_inverse,
    modular_power,
)
from crypto.primes import is_probable_prime


class NumberTheoryTests(unittest.TestCase):
    def test_gcd_handles_signs_and_zero(self) -> None:
        self.assertEqual(gcd(-54, 24), 6)
        self.assertEqual(gcd(0, 9), 9)

    def test_extended_gcd_identity(self) -> None:
        divisor, x, y = extended_gcd(240, 46)
        self.assertEqual(divisor, 2)
        self.assertEqual(240 * x + 46 * y, divisor)

    def test_modular_inverse(self) -> None:
        self.assertEqual(modular_inverse(17, 3120), 2753)
        with self.assertRaises(ValueError):
            modular_inverse(6, 12)

    def test_modular_power_matches_known_rsa_example(self) -> None:
        self.assertEqual(modular_power(65, 17, 3233), 2790)
        self.assertEqual(modular_power(2790, 2753, 3233), 65)

    def test_primality_test(self) -> None:
        for prime in (2, 3, 61, 7919, 2_147_483_647):
            self.assertTrue(is_probable_prime(prime), prime)
        for composite in (0, 1, 4, 221, 7957, 2_147_483_645):
            self.assertFalse(is_probable_prime(composite), composite)


if __name__ == "__main__":
    unittest.main()
