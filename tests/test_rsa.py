from pathlib import Path
import sys
import tempfile
import unittest


SOURCE_DIRECTORY = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from crypto import (
    DecryptionError,
    EncodingError,
    RSAPrivateKey,
    RSAPublicKey,
    decrypt_oaep,
    encrypt_oaep,
    generate_key_pair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign_pss,
    verify_pss,
)


class RSAIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_key, cls.private_key = generate_key_pair(
            bits=1024,
            primality_rounds=24,
        )

    def test_generated_key_has_requested_size(self) -> None:
        self.assertEqual(self.public_key.n.bit_length(), 1024)
        self.assertEqual(self.private_key.public_key, self.public_key)

    def test_raw_primitives_round_trip(self) -> None:
        representative = 123456789
        encrypted = self.public_key.public_operation(representative)
        self.assertEqual(
            self.private_key.private_operation(encrypted),
            representative,
        )

    def test_private_key_rejects_composite_factors(self) -> None:
        with self.assertRaises(ValueError):
            RSAPrivateKey(n=225, e=5, d=5, p=9, q=25)

    def test_private_key_rejects_negative_exponent(self) -> None:
        with self.assertRaises(ValueError):
            RSAPrivateKey(n=15, e=3, d=-1, p=3, q=5)

    def test_rsa_keys_reject_even_moduli_and_factors(self) -> None:
        with self.assertRaises(ValueError):
            RSAPublicKey(n=6, e=5)
        with self.assertRaises(ValueError):
            RSAPrivateKey(n=6, e=5, d=1, p=2, q=3)

    def test_oaep_round_trip(self) -> None:
        message = b"QR ticket secret"
        label = b"ticket-system-v1"
        ciphertext = encrypt_oaep(message, self.public_key, label)
        self.assertNotEqual(ciphertext, message)
        self.assertEqual(
            decrypt_oaep(ciphertext, self.private_key, label),
            message,
        )

    def test_oaep_is_randomized(self) -> None:
        message = b"same message"
        first = encrypt_oaep(message, self.public_key)
        second = encrypt_oaep(message, self.public_key)
        self.assertNotEqual(first, second)

    def test_oaep_rejects_tampering_and_wrong_label(self) -> None:
        ciphertext = encrypt_oaep(b"protected", self.public_key, b"correct")
        changed = bytearray(ciphertext)
        changed[-1] ^= 1
        with self.assertRaises(DecryptionError):
            decrypt_oaep(bytes(changed), self.private_key, b"correct")
        with self.assertRaises(DecryptionError):
            decrypt_oaep(ciphertext, self.private_key, b"wrong")

    def test_oaep_rejects_message_that_is_too_long(self) -> None:
        maximum = self.public_key.size_bytes - 2 * 32 - 2
        with self.assertRaises(EncodingError):
            encrypt_oaep(b"x" * (maximum + 1), self.public_key)

    def test_pss_signature_verification(self) -> None:
        ticket = b"V1|TKT-0001|EVENT-2026|STUDENT"
        signature = sign_pss(ticket, self.private_key)
        self.assertTrue(verify_pss(ticket, signature, self.public_key))
        self.assertFalse(verify_pss(ticket + b"|VIP", signature, self.public_key))

        changed_signature = bytearray(signature)
        changed_signature[10] ^= 1
        self.assertFalse(
            verify_pss(ticket, bytes(changed_signature), self.public_key)
        )

    def test_pss_is_randomized(self) -> None:
        message = b"ticket"
        first = sign_pss(message, self.private_key)
        second = sign_pss(message, self.private_key)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_pss(message, first, self.public_key))
        self.assertTrue(verify_pss(message, second, self.public_key))

    def test_key_serialization_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            public_path = Path(directory) / "public.json"
            private_path = Path(directory) / "private.json"
            save_public_key(self.public_key, public_path)
            save_private_key(self.private_key, private_path)
            self.assertEqual(load_public_key(public_path), self.public_key)
            self.assertEqual(load_private_key(private_path), self.private_key)


if __name__ == "__main__":
    unittest.main()
