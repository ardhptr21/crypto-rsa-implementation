from dataclasses import dataclass
import secrets

from .exceptions import KeyGenerationError
from .number_theory import gcd, lcm, modular_inverse, modular_power
from .primes import generate_prime, is_probable_prime


DEFAULT_PUBLIC_EXPONENT = 65_537
DEFAULT_KEY_BITS = 2_048
MINIMUM_KEY_BITS = 1_024


@dataclass(frozen=True, slots=True)
class RSAPublicKey:
    n: int
    e: int

    def __post_init__(self) -> None:
        if self.n <= 0 or self.n % 2 == 0:
            raise ValueError("modulus must be a positive odd integer")
        if self.e < 3 or self.e % 2 == 0:
            raise ValueError("public exponent must be an odd integer >= 3")
        if self.e >= self.n:
            raise ValueError("public exponent must be smaller than the modulus")

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public_operation(self, representative: int) -> int:
        if not 0 <= representative < self.n:
            raise ValueError("representative must be in the range [0, n)")
        return modular_power(representative, self.e, self.n)


@dataclass(frozen=True, slots=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    def __post_init__(self) -> None:
        if self.d <= 0:
            raise ValueError("private exponent must be positive")
        if (
            self.p <= 2
            or self.q <= 2
            or not is_probable_prime(self.p)
            or not is_probable_prime(self.q)
        ):
            raise ValueError("RSA factors must be probable primes")
        if self.p == self.q:
            raise ValueError("RSA primes must be distinct")
        if self.p * self.q != self.n:
            raise ValueError("private-key primes do not match the modulus")
        group_order = lcm(self.p - 1, self.q - 1)
        if group_order <= 0 or (self.e * self.d) % group_order != 1:
            raise ValueError("private exponent is inconsistent with the key")
        RSAPublicKey(self.n, self.e)

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    def _crt_operation(self, representative: int) -> int:
        result_mod_p = modular_power(representative, self.d % (self.p - 1), self.p)
        result_mod_q = modular_power(representative, self.d % (self.q - 1), self.q)
        q_inverse = modular_inverse(self.q, self.p)
        correction = ((result_mod_p - result_mod_q) * q_inverse) % self.p
        return (result_mod_q + correction * self.q) % self.n

    def private_operation(self, representative: int) -> int:
        if not 0 <= representative < self.n:
            raise ValueError("representative must be in the range [0, n)")

        while True:
            blinding_factor = secrets.randbelow(self.n - 3) + 2
            if gcd(blinding_factor, self.n) == 1:
                break

        blinded = (
            representative
            * modular_power(blinding_factor, self.e, self.n)
        ) % self.n
        blinded_result = self._crt_operation(blinded)
        result = (
            blinded_result * modular_inverse(blinding_factor, self.n)
        ) % self.n
        if modular_power(result, self.e, self.n) != representative:
            raise ValueError("RSA private operation failed its consistency check")
        return result


def generate_key_pair(
    bits: int = DEFAULT_KEY_BITS,
    public_exponent: int = DEFAULT_PUBLIC_EXPONENT,
    primality_rounds: int = 40,
) -> tuple[RSAPublicKey, RSAPrivateKey]:
    if bits < MINIMUM_KEY_BITS:
        raise KeyGenerationError(
            f"RSA modulus must be at least {MINIMUM_KEY_BITS} bits"
        )
    if public_exponent < 3 or public_exponent % 2 == 0:
        raise KeyGenerationError("public exponent must be an odd integer >= 3")
    if primality_rounds <= 0:
        raise KeyGenerationError("primality rounds must be positive")

    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits, public_exponent, primality_rounds)
        q = generate_prime(q_bits, public_exponent, primality_rounds)
        if p == q:
            continue

        modulus = p * q
        if modulus.bit_length() != bits:
            continue

        group_order = lcm(p - 1, q - 1)
        if gcd(public_exponent, group_order) != 1:
            continue

        try:
            private_exponent = modular_inverse(public_exponent, group_order)
        except ValueError:
            continue

        public_key = RSAPublicKey(modulus, public_exponent)
        private_key = RSAPrivateKey(
            modulus,
            public_exponent,
            private_exponent,
            p,
            q,
        )
        return public_key, private_key
