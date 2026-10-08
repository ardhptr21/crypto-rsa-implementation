import secrets

from .number_theory import gcd, modular_power


_SMALL_PRIMES = (
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
)

_DETERMINISTIC_64_BIT_BASES = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


def _passes_miller_rabin_round(
    candidate: int,
    base: int,
    odd_part: int,
    power: int,
) -> bool:
    value = modular_power(base, odd_part, candidate)
    if value in (1, candidate - 1):
        return True

    for _ in range(power - 1):
        value = (value * value) % candidate
        if value == candidate - 1:
            return True
    return False


def is_probable_prime(candidate: int, rounds: int = 40) -> bool:
    if rounds <= 0:
        raise ValueError("rounds must be positive")
    if candidate < 2:
        return False

    for prime in _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    odd_part = candidate - 1
    power = 0
    while odd_part % 2 == 0:
        power += 1
        odd_part //= 2

    if candidate < 2**64:
        bases = (base % candidate for base in _DETERMINISTIC_64_BIT_BASES)
    else:
        bases = (secrets.randbelow(candidate - 3) + 2 for _ in range(rounds))

    for base in bases:
        if base in (0, 1):
            continue
        if not _passes_miller_rabin_round(candidate, base, odd_part, power):
            return False
    return True


def generate_prime(bits: int, public_exponent: int = 65_537, rounds: int = 40) -> int:
    if bits < 2:
        raise ValueError("prime size must be at least 2 bits")
    if public_exponent < 3 or public_exponent % 2 == 0:
        raise ValueError("public exponent must be an odd integer >= 3")

    high_bit = 1 << (bits - 1)
    while True:
        candidate = secrets.randbits(bits) | high_bit | 1
        if gcd(candidate - 1, public_exponent) != 1:
            continue
        if is_probable_prime(candidate, rounds):
            return candidate
