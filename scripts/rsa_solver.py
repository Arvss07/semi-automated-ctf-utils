#!/usr/bin/env python3
"""Exact-integer RSA helpers and common CTF attacks."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys
from typing import Sequence


class RsaError(ValueError):
    """A user-facing RSA parameter or attack error."""


def is_perfect_square(n: int) -> bool:
    if n < 0:
        return False
    root = math.isqrt(n)
    return root * root == n


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    greatest, x, y = egcd(b % a, a)
    return greatest, y - (b // a) * x, x


def modinv(a: int, modulus: int) -> int | None:
    greatest, x, _ = egcd(a, modulus)
    return x % modulus if greatest == 1 else None


def int_to_bytes(number: int) -> bytes:
    if number < 0:
        raise ValueError("cannot convert a negative integer to unsigned bytes")
    if number == 0:
        return b"\x00"
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder="big")


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, byteorder="big")


def integer_nth_root(number: int, degree: int) -> tuple[int, bool]:
    """Return ``(floor(root), exact)`` using integer-only binary search."""
    if degree < 1:
        raise ValueError("degree must be positive")
    if number < 0:
        if degree % 2 == 0:
            raise ValueError("even root of a negative number is not an integer")
        root, exact = integer_nth_root(-number, degree)
        return -root, exact
    if number in {0, 1} or degree == 1:
        return number, True

    low = 0
    high = 1 << ((number.bit_length() + degree - 1) // degree)
    while low <= high:
        midpoint = (low + high) // 2
        powered = midpoint**degree
        if powered == number:
            return midpoint, True
        if powered < number:
            low = midpoint + 1
        else:
            high = midpoint - 1
    return high, False


def is_perfect_power(number: int, degree: int) -> bool:
    return integer_nth_root(number, degree)[1]


def factor_fermat(n: int, max_iterations: int = 1_000_000) -> tuple[int, int] | None:
    """Factor an odd semiprime whose factors are close."""
    if n <= 1 or max_iterations < 0:
        return None
    if n % 2 == 0:
        return (2, n // 2) if n // 2 > 1 else None

    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iterations + 1):
        difference = a * a - n
        if is_perfect_square(difference):
            b = math.isqrt(difference)
            p, q = a - b, a + b
            if p > 1 and q > 1 and p * q == n:
                return min(p, q), max(p, q)
        a += 1
    return None


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    coefficients: list[int] = []
    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        coefficients.append(quotient)
        numerator, denominator = denominator, remainder
    return coefficients


def convergents(coefficients: list[int]) -> list[tuple[int, int]]:
    values: list[tuple[int, int]] = []
    numerator_previous, numerator = 0, 1
    denominator_previous, denominator = 1, 0
    for coefficient in coefficients:
        numerator_previous, numerator = numerator, coefficient * numerator + numerator_previous
        denominator_previous, denominator = denominator, coefficient * denominator + denominator_previous
        values.append((numerator, denominator))
    return values


def wiener_attack(e: int, n: int) -> tuple[int, int, int] | None:
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        factor_sum = n - phi + 1
        discriminant = factor_sum * factor_sum - 4 * n
        if discriminant < 0 or not is_perfect_square(discriminant):
            continue
        root = math.isqrt(discriminant)
        if (factor_sum + root) % 2:
            continue
        p = (factor_sum + root) // 2
        q = (factor_sum - root) // 2
        if p > 1 and q > 1 and p * q == n:
            return min(p, q), max(p, q), d
    return None


def low_e_attack(c: int, e: int, n: int | None = None) -> int | None:
    """Recover unpadded plaintext when c is an exact e-th power."""
    del n  # The no-wrap attack does not use the modulus.
    root, exact = integer_nth_root(c, e)
    return root if exact else None


def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> int | None:
    greatest, coefficient1, coefficient2 = egcd(e1, e2)
    if greatest != 1:
        return None

    def modular_power(base: int, exponent: int) -> int | None:
        if exponent >= 0:
            return pow(base, exponent, n)
        inverse = modinv(base, n)
        return None if inverse is None else pow(inverse, -exponent, n)

    part1 = modular_power(c1, coefficient1)
    part2 = modular_power(c2, coefficient2)
    if part1 is None or part2 is None:
        return None
    return (part1 * part2) % n


def _plaintext_fields(value: int) -> dict[str, int | str]:
    raw = int_to_bytes(value)
    try:
        text = raw.decode("utf-8")
        printable = all(character.isprintable() or character in "\r\n\t" for character in text)
    except UnicodeDecodeError:
        text = ""
        printable = False
    return {
        "decrypted": value,
        "decrypted_bytes": text if printable else f"hex:{raw.hex()}",
    }


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    """Deterministic Miller–Rabin for 64-bit; probabilistic for larger n."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    import random

    random.seed(0x5253415F534F4C564552)
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _result_from_factors(
    p: int,
    q: int,
    e: int,
    n: int | None,
    c: int | None,
    d: int | None = None,
    attack: str = "supplied factors",
) -> dict[str, int | str]:
    if p <= 1 or q <= 1:
        raise RsaError("p and q must both be greater than 1")
    if p == q:
        raise RsaError("p and q must be distinct primes for standard RSA")
    if not _is_probable_prime(p):
        raise RsaError("p is not a probable prime")
    if not _is_probable_prime(q):
        raise RsaError("q is not a probable prime")
    product = p * q
    if n is not None and n != product:
        raise RsaError("p * q does not equal the supplied modulus")
    n = product
    phi = (p - 1) * (q - 1)
    if d is None:
        d = modinv(e, phi)
        if d is None:
            raise RsaError("public exponent has no inverse modulo phi(n)")

    result: dict[str, int | str] = {
        "attack": attack,
        "n": n,
        "e": e,
        "p": min(p, q),
        "q": max(p, q),
        "phi": phi,
        "d": d,
    }
    if c is not None:
        result.update(_plaintext_fields(pow(c, d, n)))
    return result


def solve_rsa(
    n: int | None,
    e: int,
    c: int | None = None,
    d: int | None = None,
    p: int | None = None,
    q: int | None = None,
    max_fermat_iterations: int = 1_000_000,
) -> dict[str, int | str]:
    """Solve using supplied secrets first, then low-e, Wiener, and Fermat."""
    if (p is None) != (q is None):
        raise RsaError("p and q must be supplied together")
    if p is not None and q is not None:
        return _result_from_factors(p, q, e, n, c, d)
    if d is not None:
        if n is None or c is None:
            raise RsaError("supplied d requires both n and c")
        result: dict[str, int | str] = {"attack": "supplied private exponent", "n": n, "e": e, "d": d}
        result.update(_plaintext_fields(pow(c, d, n)))
        return result
    if c is not None and e > 1:
        plaintext = low_e_attack(c, e)
        if plaintext is not None:
            return {"attack": "low public exponent", **_plaintext_fields(plaintext)}
    if n is None:
        raise RsaError("a modulus is required for Wiener or Fermat attacks")
    wiener = wiener_attack(e, n)
    if wiener:
        found_p, found_q, found_d = wiener
        return _result_from_factors(found_p, found_q, e, n, c, found_d, "Wiener")
    factors = factor_fermat(n, max_fermat_iterations)
    if factors:
        return _result_from_factors(*factors, e, n, c, attack="Fermat")
    raise RsaError("no configured attack succeeded")


def parse_integer(value: str | None, name: str, required: bool = False) -> int | None:
    if value is None:
        if required:
            raise RsaError(f"{name} is required")
        return None
    path = Path(value).expanduser()
    try:
        is_file = path.is_file()
        exists = path.exists()
    except OSError:
        # Very large decimal parameters are values, not plausible filesystem paths.
        is_file = False
        exists = False
    if is_file:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise RsaError(f"cannot read {name} from '{path}': {exc}") from exc
    elif exists:
        raise RsaError(f"{name} path '{path}' is not a regular file")
    else:
        text = value.strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError as exc:
            raise RsaError(f"{name} must be an integer or a file containing one") from exc


def execute_attack(args: argparse.Namespace) -> dict[str, int | str]:
    n = parse_integer(args.modulus, "n")
    e = parse_integer(args.exponent, "e", required=True)
    c = parse_integer(args.ciphertext, "c")
    p = parse_integer(args.p, "p")
    q = parse_integer(args.q, "q")
    d = parse_integer(args.d, "d")
    assert e is not None

    if e < 2:
        raise RsaError("e must be at least 2")
    if n is not None and n <= 1:
        raise RsaError("n must be greater than 1")
    if args.max_iterations < 0:
        raise RsaError("--max-iterations must be non-negative")

    if args.attack is None:
        return solve_rsa(n, e, c, d, p, q, args.max_iterations)
    if any(value is not None for value in (p, q, d)):
        raise RsaError("--attack cannot be combined with supplied p, q, or d")

    if args.attack == "lowe":
        if c is None:
            raise RsaError("low-e attack requires c")
        plaintext = low_e_attack(c, e)
        if plaintext is None:
            raise RsaError("ciphertext is not an exact e-th power")
        return {"attack": "low public exponent", **_plaintext_fields(plaintext)}

    if args.attack == "wiener":
        if n is None:
            raise RsaError("Wiener attack requires n and e")
        result = wiener_attack(e, n)
        if result is None:
            raise RsaError("Wiener attack failed")
        found_p, found_q, found_d = result
        return _result_from_factors(found_p, found_q, e, n, c, found_d, "Wiener")

    if args.attack == "fermat":
        if n is None:
            raise RsaError("Fermat attack requires n")
        factors = factor_fermat(n, args.max_iterations)
        if factors is None:
            raise RsaError("Fermat factorization failed")
        return _result_from_factors(*factors, e, n, c, attack="Fermat")

    c1 = parse_integer(args.ciphertext1, "c1", required=True)
    e1 = parse_integer(args.e1, "e1", required=True)
    e2 = parse_integer(args.e2, "e2", required=True)
    if n is None or c is None:
        raise RsaError("common-modulus attack requires n, c1, c2 (via --ciphertext), e1, and e2")
    assert c1 is not None and e1 is not None and e2 is not None
    plaintext = common_modulus_attack(c1, c, e1, e2, n)
    if plaintext is None:
        raise RsaError("common-modulus attack failed (exponents must be coprime and ciphertexts invertible)")
    return {"attack": "common modulus", "n": n, **_plaintext_fields(plaintext)}


def render_report(result: dict[str, int | str]) -> str:
    labels = {
        "attack": "Attack",
        "n": "Modulus n",
        "e": "Public exponent e",
        "p": "Prime p",
        "q": "Prime q",
        "phi": "phi(n)",
        "d": "Private exponent d",
        "decrypted": "Decrypted integer",
        "decrypted_bytes": "Decrypted bytes",
    }
    ordered = ["attack", "n", "e", "p", "q", "phi", "d", "decrypted", "decrypted_bytes"]
    lines = ["RSA solution", "=" * 60]
    lines.extend(f"{labels[key]}: {result[key]}" for key in ordered if key in result)
    return "\n".join(lines)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise RsaError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + "\n", encoding="utf-8")
    print(f"Output written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RSA cryptanalysis toolkit", allow_abbrev=False)
    parser.add_argument("-n", "--modulus", help="Modulus n or a file containing it")
    parser.add_argument("-e", "--exponent", default="65537", help="Public exponent e or file")
    parser.add_argument("-c", "--ciphertext", help="Ciphertext c (or c2) or file")
    parser.add_argument("-p", help="Prime p or file")
    parser.add_argument("-q", help="Prime q or file")
    parser.add_argument("-d", help="Private exponent d or file")
    parser.add_argument("-1", "--ciphertext1", help="Ciphertext c1 for common modulus")
    parser.add_argument("--e1", help="Exponent e1 for common modulus")
    parser.add_argument("--e2", help="Exponent e2 for common modulus")
    parser.add_argument("--attack", choices=["fermat", "wiener", "lowe", "commonmod"])
    parser.add_argument("--max-iterations", type=int, default=1_000_000, help="Fermat iteration limit")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute_attack(args)
        write_report(render_report(result), args.output)
        return 0
    except (RsaError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
