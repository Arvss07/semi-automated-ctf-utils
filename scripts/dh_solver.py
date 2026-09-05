#!/usr/bin/env python3
"""Diffie-Hellman shared-secret recovery and XOR-ciphertext decryption for CTFs."""

from __future__ import annotations

import argparse
import hashlib
import math
import re
from pathlib import Path
import sys
from typing import Sequence


class DhError(ValueError):
    """A user-facing Diffie-Hellman input or solving error."""


FLAG_PATTERNS = (
    re.compile(r"picoCTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"HTB\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CSAW\{[^}]+\}", re.IGNORECASE),
    re.compile(r"H4G\{[^}]+\}", re.IGNORECASE),
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
)

PARAM_RE = re.compile(r"^\s*(g|p|A|B|a|b|enc)\s*=\s*(\S.*?)\s*$")


def int_to_bytes(number: int, endian: str = "big") -> bytes:
    if number < 0:
        raise ValueError("cannot convert a negative integer to unsigned bytes")
    if number == 0:
        return b"\x00"
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder=endian)


def score_text(text_bytes: bytes) -> float:
    """Score bytes as likely English (same scale as xor_toolkit)."""
    if not text_bytes:
        return float("-inf")
    score = 0.0
    for byte in text_bytes:
        if byte in b"ETAOIN SHRDLUetaoinshrdlu":
            score += 2.0
        elif 65 <= byte <= 90 or 97 <= byte <= 122:
            score += 1.0
        elif byte in b"0123456789.,!?:;'\"()-_{}[]/\\":
            score += 0.35
        elif byte in b"\n\r\t ":
            score += 0.75
        elif 32 <= byte <= 126:
            score += 0.05
        else:
            score -= 4.0
    uppercase = bytes(byte for byte in text_bytes.upper() if 32 <= byte <= 126)
    for word in (b" THE ", b" AND ", b" FLAG", b" CTF", b" THIS ", b" WITH "):
        score += uppercase.count(word) * 4.0
    return score / len(text_bytes)


def is_readable(data: bytes, threshold: float = 0.90) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return True
    readable = sum(c.isprintable() or c in "\r\n\t" for c in text)
    return readable / len(text) >= threshold


def contains_flag(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    for pattern in FLAG_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def render_bytes(data: bytes) -> str:
    if is_readable(data):
        return data.decode("utf-8")
    return f"hex:{data.hex()}"


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    """Deterministic Miller-Rabin for 64-bit; probabilistic above (seeded)."""
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

    random.seed(0x44485F534F4C564552)
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


def discrete_log_small(g: int, h: int, p: int, max_steps: int) -> int | None:
    """Baby-step giant-step discrete log, bounded by max_steps.

    Returns x with pow(g, x, p) == h, or None when not found / out of budget.
    Only suitable for weak (small-prime / small-private) edge cases.
    """
    if max_steps < 1:
        raise ValueError("max_steps must be positive")
    h %= p
    if h == 1:
        return 0
    m = math.isqrt(max_steps) + 1
    table: dict[int, int] = {}
    power = 1
    for j in range(m):
        if power not in table:
            table[power] = j
        power = (power * g) % p
    try:
        inv_g = pow(g, -1, p)
    except ValueError:
        return None
    factor = pow(inv_g, m, p)
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            candidate = i * m + table[gamma]
            if candidate <= max_steps and pow(g, candidate, p) == h:
                return candidate
        gamma = (gamma * factor) % p
    return None


def parse_integer(value: str | None, name: str) -> int | None:
    if value is None:
        return None
    path = Path(value).expanduser()
    try:
        is_file = path.is_file()
        exists = path.exists()
    except OSError:
        is_file = False
        exists = False
    if is_file:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise DhError(f"cannot read {name} from '{path}': {exc}") from exc
    elif exists:
        raise DhError(f"{name} path '{path}' is not a regular file")
    else:
        text = value.strip()
    # Allow trailing comments (e.g. "123 # comment") from params files.
    text = text.split("#", 1)[0].strip().split()[0] if text.split("#", 1)[0].strip() else ""
    if not text:
        raise DhError(f"{name} is empty")
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError as exc:
            raise DhError(f"{name} must be an integer or a file containing one") from exc


def parse_enc_hex(value: str | None) -> bytes | None:
    if value is None:
        return None
    path = Path(value).expanduser()
    try:
        is_file = path.is_file()
        exists = path.exists()
    except OSError:
        is_file = False
        exists = False
    if is_file:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise DhError(f"cannot read enc from '{path}': {exc}") from exc
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            if not raw:
                raise DhError("enc file is empty") from None
            return bytes(raw)
    elif exists:
        raise DhError(f"enc path '{path}' is not a regular file")
    else:
        text = value.strip()
    compact = re.sub(r"\s+", "", text)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if not compact:
        raise DhError("enc is empty")
    if len(compact) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        raise DhError("enc must be even-length hexadecimal (or a file containing it)")
    try:
        data = bytes.fromhex(compact)
    except ValueError as exc:
        raise DhError("enc is not valid hexadecimal") from exc
    if not data:
        raise DhError("enc is empty")
    return data


def parse_params_file(path: str) -> dict[str, str]:
    filepath = Path(path).expanduser()
    if not filepath.is_file():
        raise DhError(f"params file '{filepath}' was not found")
    try:
        text = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise DhError(f"cannot read params file '{filepath}': {exc}") from exc
    params: dict[str, str] = {}
    for line in text.splitlines():
        match = PARAM_RE.match(line)
        if match:
            params[match.group(1)] = match.group(2).strip()
    return params


def looks_like_dh(text: str) -> bool:
    """Return True when text has DH params shape (g/p/A/B/a/b + enc)."""
    found = set()
    for line in text.splitlines():
        match = PARAM_RE.match(line)
        if match:
            found.add(match.group(1))
    if "p" not in found or "enc" not in found:
        return False
    return len(found & {"g", "A", "B", "a", "b"}) >= 1 and len(found) >= 3


def repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def candidate_keys(shared: int) -> list[tuple[str, bytes]]:
    """Ordered key-derivation attempts for a DH shared secret."""
    shared_bytes = int_to_bytes(shared, "big")
    shared_le = int_to_bytes(shared, "little")
    keys: list[tuple[str, bytes]] = [
        ("shared%256 single-byte", bytes([shared % 256])),
    ]
    try:
        keys.append(("sha256(BE)", hashlib.sha256(shared_bytes).digest()))
        keys.append(("sha1(BE)", hashlib.sha1(shared_bytes).digest()))  # noqa: S324
        keys.append(("md5(BE)", hashlib.md5(shared_bytes).digest()))  # noqa: S324
        keys.append(("sha512(BE)", hashlib.sha512(shared_bytes).digest()))
        keys.append(("sha256(str(shared))", hashlib.sha256(str(shared).encode()).digest()))
    except (ValueError, OverflowError):
        pass
    keys.append(("BE bytes", shared_bytes))
    keys.append(("LE bytes", shared_le))
    return keys


def decrypt_candidates(enc: bytes, shared: int, top: int) -> list[dict[str, object]]:
    scored: list[dict[str, object]] = []
    for method, key in candidate_keys(shared):
        stream = (key * ((len(enc) // len(key)) + 1))[: len(enc)]
        plain = bytes(a ^ b for a, b in zip(enc, stream))
        base = score_text(plain)
        flag = contains_flag(plain)
        score = base + (50.0 if flag else 0.0) + (2.0 if is_readable(plain) else 0.0)
        scored.append(
            {
                "method": method,
                "key_hex": key.hex() if len(key) <= 64 else key.hex()[:128] + "...",
                "key_len": len(key),
                "score": score,
                "flag": flag,
                "plaintext": plain,
            }
        )
    scored.sort(key=lambda item: float(item["score"]), reverse=True)
    return scored[: max(1, top)]


def validate_params(g: int, p: int, A: int | None, B: int | None) -> list[str]:
    warnings: list[str] = []
    if p < 3:
        raise DhError("p must be greater than 2")
    if p % 2 == 0:
        warnings.append("p is even and cannot be a DH prime")
    elif not is_probable_prime(p):
        warnings.append("p is not a probable prime; thought you had a prime?")
    if g < 2 or g >= p:
        raise DhError("g must satisfy 2 <= g < p")
    if g == 2:
        pass
    elif g < 2:
        warnings.append("g is unusually small")
    if p.bit_length() < 512:
        warnings.append(f"p is only {p.bit_length()} bits; small enough to be weak")
    # Small-subgroup / trivial-value checks.
    for label, value in (("A", A), ("B", B)):
        if value is None:
            continue
        if value <= 1 or value >= p:
            warnings.append(f"{label}={value} is trivial or out of range [2, p-1]")
        elif value == p - 1:
            warnings.append(f"{label} == p-1 (order 2 subgroup element)")
    # Bounded generator-order probe: g should not have a very small order
    # (e.g. g=1 mod p, or confinement to {1, p-1}). Larger proper subgroups
    # such as order (p-1)/2 for a safe prime are normal and not flagged.
    for small_q in (2, 3, 5, 7):
        try:
            if pow(g, small_q, p) == 1:
                warnings.append(f"g has very small order {small_q} mod p; secrets collapse to a tiny set")
                break
        except ValueError:
            break
    return warnings


def resolve_params(args: argparse.Namespace) -> tuple[dict[str, int | None], bytes, str | None]:
    file_params: dict[str, str] = {}
    params_source: str | None = None
    positional = args.input
    if positional is not None:
        path = Path(positional).expanduser()
        if path.is_file():
            file_params = parse_params_file(str(path))
            params_source = str(path)
    if args.params is not None:
        file_params = parse_params_file(args.params)
        params_source = args.params

    def pick(name: str, cli: str | None) -> str | None:
        if cli is not None:
            # CLI may itself be a file path (rsa_solver convention).
            path = Path(cli).expanduser()
            try:
                if path.is_file():
                    return path.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError) as exc:
                raise DhError(f"cannot read {name} from '{path}': {exc}") from exc
            if path.exists():
                raise DhError(f"{name} path '{path}' is not a regular file")
            return cli
        return file_params.get(name)

    g = parse_integer(pick("g", args.g), "g")
    p = parse_integer(pick("p", args.p), "p")
    A = parse_integer(pick("A", args.A_pub), "A")
    B = parse_integer(pick("B", args.B_pub), "B")
    a = parse_integer(pick("a", args.a_priv), "a")
    b = parse_integer(pick("b", args.b_priv), "b")

    enc: bytes | None = None
    if args.enc_hex is not None:
        enc = parse_enc_hex(args.enc_hex)
    elif args.enc_file is not None:
        enc = parse_enc_hex(args.enc_file)
    elif "enc" in file_params:
        enc = parse_enc_hex(file_params["enc"])
    if enc is None:
        raise DhError("enc ciphertext is required (--enc-hex, --enc-file, or params file)")
    if g is None:
        raise DhError("g is required (--g or params file)")
    if p is None:
        raise DhError("p is required (--p or params file)")
    return {"g": g, "p": p, "A": A, "B": B, "a": a, "b": b}, enc, params_source


def compute_shared(
    g: int, p: int, A: int | None, B: int | None, a: int | None, b: int | None, max_dlp_steps: int
) -> tuple[int, str, list[str]]:
    notes: list[str] = []
    if A is not None and b is not None:
        shared = pow(A, b, p)
        method = "pow(A, b, p)"
        if B is not None and B != pow(g, b, p):
            notes.append("B != pow(g, b, p); params are inconsistent")
        if a is not None and A != pow(g, a, p):
            notes.append("A != pow(g, a, p); params are inconsistent")
        return shared, method, notes
    if B is not None and a is not None:
        shared = pow(B, a, p)
        method = "pow(B, a, p)"
        if A is not None and A != pow(g, a, p):
            notes.append("A != pow(g, a, p); params are inconsistent")
        return shared, method, notes
    if a is not None and b is not None:
        A_calc = pow(g, a, p)
        B_calc = pow(g, b, p)
        shared = pow(A_calc, b, p)
        method = "pow(g, a*b, p) via supplied a and b"
        if A is not None and A != A_calc:
            notes.append("supplied A != pow(g, a, p)")
        if B is not None and B != B_calc:
            notes.append("supplied B != pow(g, b, p)")
        return shared, method, notes
    # No private exponent: try bounded DLP for weak edge cases only.
    if A is not None and max_dlp_steps > 0:
        recovered = discrete_log_small(g, A, p, max_dlp_steps)
        if recovered is not None:
            notes.append(f"recovered a={recovered} by bounded DLP (weak params)")
            if B is None:
                raise DhError(
                    "recovered a from A but B is missing; need B to compute pow(B, a, p)"
                )
            return pow(B, recovered, p), "pow(B, recovered-a, p) via DLP", notes
    if B is not None and max_dlp_steps > 0:
        recovered = discrete_log_small(g, B, p, max_dlp_steps)
        if recovered is not None:
            notes.append(f"recovered b={recovered} by bounded DLP (weak params)")
            if A is None:
                raise DhError(
                    "recovered b from B but A is missing; need A to compute pow(A, b, p)"
                )
            return pow(A, recovered, p), "pow(A, recovered-b, p) via DLP", notes
    raise DhError(
        "need a private exponent (a or b) with its peer public (B or A). "
        "Large-prime DLP is infeasible here; try SageMath/Pohlig-Hellman only when "
        "p-1 is smooth or the private is tiny (see --max-dlp-steps)."
    )


def render_report(
    params: dict[str, int | None],
    enc: bytes,
    shared: int,
    method: str,
    warnings: list[str],
    candidates: list[dict[str, object]],
) -> str:
    g = params["g"]
    p = params["p"]
    assert g is not None and p is not None
    lines = [
        "DH solution",
        "=" * 60,
        f"Method: {method}",
        f"g: {g}",
        f"p bits: {p.bit_length()}",
        f"p prime (probable): {is_probable_prime(p)}",
    ]
    for label in ("A", "B", "a", "b"):
        value = params[label]
        if value is not None:
            text = str(value)
            lines.append(f"{label}: {text[:120]}{'...' if len(text) > 120 else ''}")
    lines.extend(
        [
            f"Shared: {shared}",
            f"Shared hex: {int_to_bytes(shared).hex()[:160]}{'...' if len(int_to_bytes(shared).hex()) > 160 else ''}",
            f"Shared low byte: 0x{shared % 256:02x} ({shared % 256})",
            f"enc bytes: {len(enc)}",
        ]
    )
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in warnings)
    lines.append("")
    lines.append(f"Top {len(candidates)} key candidates (repeating-XOR):")
    for rank, item in enumerate(candidates, 1):
        plain = item["plaintext"]
        assert isinstance(plain, bytes)
        lines.extend(
            [
                "",
                f"[{rank}] {item['method']}, key_hex={item['key_hex']}, score={float(item['score']):.3f}",
                f"Flag: {item['flag']}" if item["flag"] else "Flag: none",
                render_bytes(plain),
            ]
        )
    return "\n".join(lines)


def write_report(report: str, output: str, sources: set[str], force: bool) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser().resolve()
    if not path.parent.exists():
        raise DhError(f"output directory '{path.parent}' does not exist")
    for src in sources:
        try:
            if str(Path(src).expanduser().resolve()) == str(path):
                raise DhError("output path must not overwrite an input file")
        except OSError:
            pass
    if path.exists() and not force:
        raise DhError(f"output path '{path}' already exists; use --force to overwrite")
    try:
        path.write_text(report + "\n", encoding="utf-8")
    except OSError as exc:
        raise DhError(f"cannot write '{path}': {exc}") from exc
    print(f"Output written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Solve Diffie-Hellman challenges with a supplied private exponent and XOR ciphertext",
        allow_abbrev=False,
    )
    parser.add_argument("input", nargs="?", help="Params file with g/p/A/B/a/b/enc lines")
    parser.add_argument("--params", help="Explicit params file")
    parser.add_argument("--g", help="Generator g or file containing it")
    parser.add_argument("--p", help="Prime p or file containing it")
    parser.add_argument("--A", dest="A_pub", help="Server public A or file")
    parser.add_argument("--B", dest="B_pub", help="Client public B or file")
    parser.add_argument("--a", dest="a_priv", help="Server private a or file")
    parser.add_argument("--b", dest="b_priv", help="Client private b or file")
    parser.add_argument("--enc-hex", help="Ciphertext as hex (whitespace/0x tolerated)")
    parser.add_argument("--enc-file", help="File with hex ciphertext (or raw bytes)")
    parser.add_argument("-n", "--top", type=int, default=5, help="Key candidates to show")
    parser.add_argument(
        "--max-dlp-steps",
        type=int,
        default=2_000_000,
        help="Bounded DLP budget when no private is supplied (0 disables)",
    )
    parser.add_argument("--output", default="console", help="Report output path")
    parser.add_argument("--force", action="store_true", help="Allow overwriting an existing output file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.top < 1:
            raise DhError("--top must be at least 1")
        if args.max_dlp_steps < 0:
            raise DhError("--max-dlp-steps must be non-negative")
        params, enc, params_source = resolve_params(args)
        g = params["g"]
        p = params["p"]
        assert g is not None and p is not None
        warnings = validate_params(g, p, params["A"], params["B"])
        shared, method, notes = compute_shared(
            g, p, params["A"], params["B"], params["a"], params["b"], args.max_dlp_steps
        )
        warnings.extend(notes)
        if shared in (0, 1):
            warnings.append(f"shared={shared} is trivial; XOR key is degenerate")
        candidates = decrypt_candidates(enc, shared, args.top)
        report = render_report(params, enc, shared, method, warnings, candidates)
        sources = {s for s in (params_source, args.enc_file) if s}
        write_report(report, args.output, sources, args.force)
        return 0
    except (DhError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
