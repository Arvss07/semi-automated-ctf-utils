#!/usr/bin/env python3
"""Single-byte, repeating-key, and crib-drag XOR tooling for CTFs."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from typing import NamedTuple, Sequence


class XorError(ValueError):
    """A user-facing XOR input error."""


class CribResult(NamedTuple):
    position: int
    key: bytes | None
    decrypted: bytes
    score: float
    key_pattern: str


def score_text(text_bytes: bytes) -> float:
    """Score bytes as likely English without dropping invalid bytes."""
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


def hamming_distance(bytes1: bytes, bytes2: bytes) -> int:
    if len(bytes1) != len(bytes2):
        raise ValueError("byte sequences must be equal length")
    return sum((left ^ right).bit_count() for left, right in zip(bytes1, bytes2))


def normalize_hamming_distance(data: bytes, key_len: int) -> float:
    if key_len < 1:
        raise ValueError("key length must be positive")
    blocks = [
        data[index : index + key_len]
        for index in range(0, min(len(data), key_len * 8), key_len)
        if len(data[index : index + key_len]) == key_len
    ]
    if len(blocks) < 2:
        return float("inf")
    distances = [
        hamming_distance(blocks[index], blocks[index + 1]) / key_len
        for index in range(len(blocks) - 1)
    ]
    return sum(distances) / len(distances)


def find_xor_key_length(data: bytes, min_len: int = 1, max_len: int = 50) -> list[tuple[int, float]]:
    if min_len < 1 or max_len < min_len:
        raise ValueError("invalid key-length range")
    candidates = [
        (length, normalize_hamming_distance(data, length))
        for length in range(min_len, max_len + 1)
    ]
    return sorted(
        (candidate for candidate in candidates if candidate[1] != float("inf")),
        key=lambda item: item[1],
    )[:10]


def single_byte_xor(data: bytes, key: int | bytes | str) -> bytes:
    if isinstance(key, str):
        encoded = key.encode("utf-8")
        if len(encoded) != 1:
            raise ValueError("string key must encode to exactly one byte")
        key_byte = encoded[0]
    elif isinstance(key, bytes):
        if len(key) != 1:
            raise ValueError("bytes key must contain exactly one byte")
        key_byte = key[0]
    else:
        if not 0 <= key <= 255:
            raise ValueError("integer key must be between 0 and 255")
        key_byte = key
    return bytes(byte ^ key_byte for byte in data)


def brute_force_single_byte(data: bytes) -> list[tuple[int, bytes, float]]:
    results = [
        (key, single_byte_xor(data, key), score_text(single_byte_xor(data, key)))
        for key in range(256)
    ]
    return sorted(results, key=lambda item: item[2], reverse=True)


def repeating_key_xor(data: bytes, key: bytes | str) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise ValueError("key must not be empty")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def solve_repeating_key_xor(data: bytes, key_len: int) -> bytes | None:
    if key_len < 1:
        raise ValueError("key length must be positive")
    if len(data) < key_len * 5:
        return None
    key = bytearray()
    for offset in range(key_len):
        column = data[offset::key_len]
        best = max(range(256), key=lambda candidate: score_text(single_byte_xor(column, candidate)))
        key.append(best)
    return bytes(key)


def _partial_decrypt(data: bytes, assignments: list[int | None]) -> bytes:
    output = bytearray()
    for index, byte in enumerate(data):
        key_byte = assignments[index % len(assignments)]
        output.append(byte ^ key_byte if key_byte is not None else ord("?"))
    return bytes(output)


def crib_drag(data: bytes, crib: bytes | str, key_len: int | None = None) -> list[CribResult]:
    """Align a crib and recover key bytes at their true repeating-key phase."""
    if isinstance(crib, str):
        crib = crib.encode("utf-8")
    if not crib:
        raise ValueError("crib must not be empty")
    if len(crib) > len(data):
        return []
    if key_len is None:
        key_len = len(crib)
    if key_len < 1:
        raise ValueError("key length must be positive")

    results: list[CribResult] = []
    for position in range(len(data) - len(crib) + 1):
        assignments: list[int | None] = [None] * key_len
        consistent = True
        for offset, plain_byte in enumerate(crib):
            key_index = (position + offset) % key_len
            key_byte = data[position + offset] ^ plain_byte
            existing = assignments[key_index]
            if existing is not None and existing != key_byte:
                consistent = False
                break
            assignments[key_index] = key_byte
        if not consistent:
            continue

        complete = all(value is not None for value in assignments)
        key = bytes(value for value in assignments if value is not None) if complete else None
        decrypted = repeating_key_xor(data, key) if key is not None else _partial_decrypt(data, assignments)
        pattern = " ".join("??" if value is None else f"{value:02x}" for value in assignments)
        score = score_text(decrypted) - assignments.count(None)
        results.append(CribResult(position, key, decrypted, score, pattern))

    return sorted(results, key=lambda item: item.score, reverse=True)


def render_bytes(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return f"hex:{data.hex()}"
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    if text and printable / len(text) < 0.9:
        return f"hex:{data.hex()}"
    return text


def resolve_input(args: argparse.Namespace) -> bytes:
    supplied = [args.input is not None, args.file is not None, args.hex_value is not None, args.text is not None]
    if sum(supplied) != 1:
        raise XorError("provide exactly one INPUT, --file PATH, --hex VALUE, or --text VALUE")
    if args.file is not None:
        path = Path(args.file).expanduser()
        if not path.is_file():
            raise XorError(f"input file '{path}' was not found")
        return path.read_bytes()
    if args.hex_value is not None:
        compact = re.sub(r"\s+", "", args.hex_value)
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise XorError("--hex input is not valid hexadecimal") from exc
    if args.text is not None:
        return args.text.encode("utf-8")

    value = args.input
    assert value is not None
    path = Path(value).expanduser()
    if path.is_file():
        return path.read_bytes()
    if path.exists():
        raise XorError(f"input path '{path}' is not a regular file")
    compact = re.sub(r"\s+", "", value)
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return bytes.fromhex(compact)
    return value.encode("utf-8")


def _known_key(args: argparse.Namespace) -> bytes | None:
    if args.key and args.key_hex:
        raise XorError("use only one of --key or --key-hex")
    if args.key_hex:
        try:
            key = bytes.fromhex(re.sub(r"\s+", "", args.key_hex))
        except ValueError as exc:
            raise XorError("--key-hex is not valid hexadecimal") from exc
        if not key:
            raise XorError("key must not be empty")
        return key
    if args.key:
        return args.key.encode("utf-8")
    return None


def analyze(args: argparse.Namespace, data: bytes) -> str:
    if args.top < 1:
        raise XorError("--top must be at least 1")
    if args.key_length is not None and args.key_length < 1:
        raise XorError("--key-length must be at least 1")

    if args.mode == "detect":
        lengths = find_xor_key_length(data, max_len=min(50, max(1, len(data) // 2)))
        if not lengths:
            raise XorError("not enough data to estimate a repeating key length")
        return "Likely key lengths (normalized Hamming distance):\n" + "\n".join(
            f"  Length {length}: {distance:.3f}" for length, distance in lengths[: args.top]
        )

    if args.mode == "single":
        lines = [f"Single-byte XOR - top {args.top} candidates:"]
        for key, decrypted, score in brute_force_single_byte(data)[: args.top]:
            character = chr(key) if 32 <= key < 127 else "?"
            lines.extend(
                ["", f"Key 0x{key:02x} ({character}), score={score:.3f}", render_bytes(decrypted)]
            )
        return "\n".join(lines)

    if args.mode == "repeating":
        key = _known_key(args)
        if key is not None:
            return f"Key (hex): {key.hex()}\nDecrypted:\n{render_bytes(repeating_key_xor(data, key))}"
        if args.key_length is not None:
            key = solve_repeating_key_xor(data, args.key_length)
            if key is None:
                raise XorError("not enough data for the requested key length")
            return f"Detected key (hex): {key.hex()}\nDecrypted:\n{render_bytes(repeating_key_xor(data, key))}"

        lengths = find_xor_key_length(data, max_len=min(20, max(1, len(data) // 2)))
        if not lengths:
            raise XorError("not enough data to estimate a repeating key")
        candidates: list[tuple[float, int, bytes, bytes]] = []
        for length, _ in lengths[:5]:
            key = solve_repeating_key_xor(data, length)
            if key is not None:
                decrypted = repeating_key_xor(data, key)
                candidates.append((score_text(decrypted), length, key, decrypted))
        if not candidates:
            raise XorError("not enough data to solve a repeating key")
        candidates.sort(reverse=True, key=lambda item: item[0])
        lines = ["Repeating-key XOR candidates:"]
        for score, length, key, decrypted in candidates[: args.top]:
            lines.extend(
                [
                    "",
                    f"Length {length}, key hex {key.hex()}, score={score:.3f}",
                    render_bytes(decrypted),
                ]
            )
        return "\n".join(lines)

    crib = _known_key(args)
    if crib is None:
        raise XorError("crib mode requires --key or --key-hex as known plaintext")
    results = crib_drag(data, crib, args.key_length)
    if not results:
        raise XorError("crib produced no consistent alignments")
    lines = [f"Crib-drag results for {render_bytes(crib)!r}:"]
    for result in results[: args.top]:
        key_text = result.key.hex() if result.key is not None else f"partial [{result.key_pattern}]"
        lines.extend(
            [
                "",
                f"Position {result.position}, key {key_text}, score={result.score:.3f}",
                render_bytes(result.decrypted),
            ]
        )
    return "\n".join(lines)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise XorError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + ("" if report.endswith("\n") else "\n"), encoding="utf-8")
    print(f"Output written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze XOR ciphertext", allow_abbrev=False)
    parser.add_argument("input", nargs="?", help="Existing file, hexadecimal value, or literal text")
    parser.add_argument("--file", help="Explicit binary input file")
    parser.add_argument("--hex", dest="hex_value", help="Explicit hexadecimal ciphertext")
    parser.add_argument("--text", help="Explicit literal ciphertext")
    parser.add_argument("-m", "--mode", choices=["single", "repeating", "detect", "crib"], default="single")
    parser.add_argument("-k", "--key", help="UTF-8 key, or known plaintext in crib mode")
    parser.add_argument("--key-hex", help="Hexadecimal key, or hexadecimal crib")
    parser.add_argument("-l", "--key-length", type=int, help="Repeating key length")
    parser.add_argument("-n", "--top", type=int, default=5, help="Number of candidates")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = resolve_input(args)
        if not data:
            raise XorError("input is empty")
        report = analyze(args, data)
        write_report(report, args.output)
        return 0
    except (XorError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
