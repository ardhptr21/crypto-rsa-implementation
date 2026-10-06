def gcd(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    x = old_s if a >= 0 else -old_s
    y = old_t if b >= 0 else -old_t
    return old_r, x, y


def modular_inverse(value: int, modulus: int) -> int:
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    divisor, coefficient, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValueError("value has no modular inverse")
    return coefficient % modulus


def modular_power(base: int, exponent: int, modulus: int) -> int:
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1 % modulus
    base %= modulus

    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1

    return result


def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a // gcd(a, b) * b)
