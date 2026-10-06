import hashlib
import hmac
import secrets

from .encoding import HASH_LENGTH, bytes_to_integer, integer_to_bytes, mgf1, xor_bytes
from .exceptions import DecryptionError, EncodingError
from .keys import RSAPrivateKey, RSAPublicKey


def encrypt_oaep(message: bytes, public_key: RSAPublicKey, label: bytes = b"") -> bytes:
    if not isinstance(message, bytes) or not isinstance(label, bytes):
        raise TypeError("message and label must be bytes")

    modulus_length = public_key.size_bytes
    maximum_length = modulus_length - 2 * HASH_LENGTH - 2
    if len(message) > maximum_length:
        raise EncodingError(
            f"message is too long; maximum for this key is {maximum_length} bytes"
        )

    label_hash = hashlib.sha256(label).digest()
    padding = b"\x00" * (modulus_length - len(message) - 2 * HASH_LENGTH - 2)
    data_block = label_hash + padding + b"\x01" + message
    seed = secrets.token_bytes(HASH_LENGTH)

    data_mask = mgf1(seed, modulus_length - HASH_LENGTH - 1)
    masked_data = xor_bytes(data_block, data_mask)
    seed_mask = mgf1(masked_data, HASH_LENGTH)
    masked_seed = xor_bytes(seed, seed_mask)
    encoded_message = b"\x00" + masked_seed + masked_data

    representative = bytes_to_integer(encoded_message)
    encrypted = public_key.public_operation(representative)
    return integer_to_bytes(encrypted, modulus_length)


def decrypt_oaep(
    ciphertext: bytes,
    private_key: RSAPrivateKey,
    label: bytes = b"",
) -> bytes:
    if not isinstance(ciphertext, bytes) or not isinstance(label, bytes):
        raise TypeError("ciphertext and label must be bytes")

    modulus_length = private_key.size_bytes
    if len(ciphertext) != modulus_length:
        raise DecryptionError("ciphertext could not be decrypted")

    encrypted = bytes_to_integer(ciphertext)
    if encrypted >= private_key.n:
        raise DecryptionError("ciphertext could not be decrypted")

    try:
        representative = private_key.private_operation(encrypted)
        encoded_message = integer_to_bytes(representative, modulus_length)
        leading_byte = encoded_message[0]
        masked_seed = encoded_message[1 : HASH_LENGTH + 1]
        masked_data = encoded_message[HASH_LENGTH + 1 :]

        seed_mask = mgf1(masked_data, HASH_LENGTH)
        seed = xor_bytes(masked_seed, seed_mask)
        data_mask = mgf1(seed, modulus_length - HASH_LENGTH - 1)
        data_block = xor_bytes(masked_data, data_mask)

        expected_label_hash = hashlib.sha256(label).digest()
        actual_label_hash = data_block[:HASH_LENGTH]
        padding_and_message = data_block[HASH_LENGTH:]

        separator_index = -1
        malformed_padding = False
        for index, byte in enumerate(padding_and_message):
            if byte == 1:
                separator_index = index
                break
            if byte != 0:
                malformed_padding = True

        valid = (
            leading_byte == 0
            and hmac.compare_digest(actual_label_hash, expected_label_hash)
            and not malformed_padding
            and separator_index >= 0
        )
        if not valid:
            raise DecryptionError("ciphertext could not be decrypted")
        return padding_and_message[separator_index + 1 :]
    except DecryptionError:
        raise
    except (IndexError, ValueError, EncodingError) as error:
        raise DecryptionError("ciphertext could not be decrypted") from error
