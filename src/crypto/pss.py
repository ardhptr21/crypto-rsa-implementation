import hashlib
import hmac
import secrets

from .encoding import HASH_LENGTH, bytes_to_integer, integer_to_bytes, mgf1, xor_bytes
from .exceptions import EncodingError
from .keys import RSAPrivateKey, RSAPublicKey


TRAILER_BYTE = 0xBC


def _encode_pss(message: bytes, encoded_bits: int, salt_length: int) -> bytes:
    message_hash = hashlib.sha256(message).digest()
    encoded_length = (encoded_bits + 7) // 8
    if encoded_length < HASH_LENGTH + salt_length + 2:
        raise EncodingError("RSA key is too small for the selected PSS salt")

    salt = secrets.token_bytes(salt_length)
    digest_input = b"\x00" * 8 + message_hash + salt
    digest = hashlib.sha256(digest_input).digest()

    zero_padding = b"\x00" * (encoded_length - salt_length - HASH_LENGTH - 2)
    data_block = zero_padding + b"\x01" + salt
    data_mask = mgf1(digest, encoded_length - HASH_LENGTH - 1)
    masked_data = bytearray(xor_bytes(data_block, data_mask))

    unused_bits = 8 * encoded_length - encoded_bits
    if unused_bits:
        masked_data[0] &= 0xFF >> unused_bits

    return bytes(masked_data) + digest + bytes([TRAILER_BYTE])


def sign_pss(
    message: bytes,
    private_key: RSAPrivateKey,
    salt_length: int = HASH_LENGTH,
) -> bytes:
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if salt_length < 0:
        raise ValueError("salt length must be non-negative")

    encoded_bits = private_key.n.bit_length() - 1
    encoded = _encode_pss(message, encoded_bits, salt_length)
    representative = bytes_to_integer(encoded)
    signature = private_key.private_operation(representative)
    return integer_to_bytes(signature, private_key.size_bytes)


def verify_pss(
    message: bytes,
    signature: bytes,
    public_key: RSAPublicKey,
    salt_length: int = HASH_LENGTH,
) -> bool:
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise TypeError("message and signature must be bytes")
    if salt_length < 0:
        raise ValueError("salt length must be non-negative")
    if len(signature) != public_key.size_bytes:
        return False

    signature_value = bytes_to_integer(signature)
    if signature_value >= public_key.n:
        return False

    encoded_bits = public_key.n.bit_length() - 1
    encoded_length = (encoded_bits + 7) // 8
    if encoded_length < HASH_LENGTH + salt_length + 2:
        return False

    try:
        representative = public_key.public_operation(signature_value)
        encoded = integer_to_bytes(representative, encoded_length)
    except (ValueError, EncodingError):
        return False

    if encoded[-1] != TRAILER_BYTE:
        return False

    masked_data_length = encoded_length - HASH_LENGTH - 1
    masked_data = bytearray(encoded[:masked_data_length])
    digest = encoded[masked_data_length:-1]
    unused_bits = 8 * encoded_length - encoded_bits
    if unused_bits and masked_data[0] & (0xFF << (8 - unused_bits)):
        return False

    data_mask = mgf1(digest, masked_data_length)
    data_block = bytearray(xor_bytes(bytes(masked_data), data_mask))
    if unused_bits:
        data_block[0] &= 0xFF >> unused_bits

    zero_padding_length = encoded_length - HASH_LENGTH - salt_length - 2
    if data_block[:zero_padding_length] != b"\x00" * zero_padding_length:
        return False
    if data_block[zero_padding_length] != 1:
        return False

    salt = bytes(data_block[-salt_length:]) if salt_length else b""
    message_hash = hashlib.sha256(message).digest()
    expected_digest = hashlib.sha256(b"\x00" * 8 + message_hash + salt).digest()
    return hmac.compare_digest(digest, expected_digest)
