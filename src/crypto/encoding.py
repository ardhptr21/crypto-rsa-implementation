import hashlib

from .exceptions import EncodingError


HASH_NAME = "sha256"
HASH_LENGTH = hashlib.new(HASH_NAME).digest_size


def integer_to_bytes(value: int, length: int) -> bytes:
    if value < 0:
        raise EncodingError("integer must be non-negative")
    if length < 0:
        raise EncodingError("length must be non-negative")
    if value >= 256**length:
        raise EncodingError("integer is too large for the requested length")
    return value.to_bytes(length, "big")


def bytes_to_integer(data: bytes) -> int:
    return int.from_bytes(data, "big")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise EncodingError("byte strings must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))


def mgf1(seed: bytes, mask_length: int, hash_name: str = HASH_NAME) -> bytes:
    if mask_length < 0:
        raise EncodingError("mask length must be non-negative")

    digest_size = hashlib.new(hash_name).digest_size
    if mask_length > (2**32) * digest_size:
        raise EncodingError("requested mask is too long")

    output = bytearray()
    counter = 0
    while len(output) < mask_length:
        counter_bytes = counter.to_bytes(4, "big")
        output.extend(hashlib.new(hash_name, seed + counter_bytes).digest())
        counter += 1
    return bytes(output[:mask_length])
