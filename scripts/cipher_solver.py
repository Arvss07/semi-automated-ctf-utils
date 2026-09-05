#!/usr/bin/env python3
"""Classical Caesar, Vigenere, and substitution analysis for CTF text."""

from __future__ import annotations

import argparse
from collections import Counter
from functools import reduce
from math import gcd
from pathlib import Path
import re
import sys
from typing import Sequence


ENGLISH_FREQ = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}
ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


class CipherError(ValueError):
    """A user-facing cipher input error."""


def clean_text(text: str) -> str:
    """Return only ASCII letters, normalized to uppercase."""
    return re.sub(r"[^A-Za-z]", "", text).upper()


def letter_score(text: str) -> float:
    """Return the negative chi-square distance from English frequencies."""
    cleaned = clean_text(text)
    if not cleaned:
        return float("-inf")
    counts = Counter(cleaned)
    total = len(cleaned)
    chi_square = 0.0
    for letter, expected_frequency in ENGLISH_FREQ.items():
        expected = expected_frequency * total
        observed = counts.get(letter, 0)
        chi_square += ((observed - expected) ** 2) / expected
    return -chi_square


def caesar_decode(text: str, shift: int) -> str:
    """Decode ASCII letters with a Caesar shift and preserve punctuation."""
    result: list[str] = []
    for character in text.upper():
        if "A" <= character <= "Z":
            result.append(chr((ord(character) - ord("A") - shift) % 26 + ord("A")))
        else:
            result.append(character)
    return "".join(result)


def caesar_brute_force(text: str) -> list[tuple[int, str, float]]:
    results = [
        (shift, caesar_decode(text, shift), letter_score(caesar_decode(text, shift)))
        for shift in range(26)
    ]
    return sorted(results, key=lambda item: item[2], reverse=True)


def kasiski_examination(text: str, min_seq: int = 3, max_seq: int = 5) -> list[tuple[int, int]] | None:
    """Return likely Vigenere lengths based on repeated-sequence spacing."""
    cleaned = clean_text(text)
    distances: list[int] = []
    for sequence_length in range(min_seq, max_seq + 1):
        positions: dict[str, list[int]] = {}
        for index in range(len(cleaned) - sequence_length + 1):
            sequence = cleaned[index : index + sequence_length]
            positions.setdefault(sequence, []).append(index)
        for matches in positions.values():
            distances.extend(
                matches[index + 1] - matches[index]
                for index in range(len(matches) - 1)
            )

    if not distances:
        return None
    counts: Counter[int] = Counter()
    for distance in distances:
        for candidate in range(2, min(21, distance + 1)):
            if distance % candidate == 0:
                counts[candidate] += 1
    return counts.most_common(5) or None


def index_of_coincidence(text: str, length: int = 1) -> float:
    cleaned = clean_text(text)
    if length < 1:
        raise ValueError("length must be positive")
    columns = [cleaned[index::length] for index in range(length)]
    values: list[float] = []
    for column in columns:
        total = len(column)
        if total <= 1:
            values.append(0.0)
            continue
        counts = Counter(column)
        values.append(sum(count * (count - 1) for count in counts.values()) / (total * (total - 1)))
    return sum(values) / len(values) if values else 0.0


def estimate_vigenere_key_length(text: str, max_length: int = 20) -> list[tuple[int, float]] | None:
    cleaned = clean_text(text)
    if len(cleaned) < 30:
        return None
    upper = min(max_length, max(1, len(cleaned) // 5))
    scores = [(length, index_of_coincidence(cleaned, length)) for length in range(1, upper + 1)]
    kasiski = dict(kasiski_examination(cleaned) or [])
    scores.sort(key=lambda item: (item[1] + kasiski.get(item[0], 0) * 0.001), reverse=True)
    return scores[:5]


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt with a known Vigenere key while preserving nonletters."""
    normalized_key = clean_text(key)
    if not normalized_key:
        raise ValueError("key must contain at least one ASCII letter")
    result: list[str] = []
    key_index = 0
    for character in text.upper():
        if "A" <= character <= "Z":
            shift = ord(normalized_key[key_index % len(normalized_key)]) - ord("A")
            result.append(chr((ord(character) - ord("A") - shift) % 26 + ord("A")))
            key_index += 1
        else:
            result.append(character)
    return "".join(result)


def vigenere_frequency_solve(text: str, key_length: int) -> str | None:
    """Recover the encryption/decryption key by solving each Caesar column."""
    cleaned = clean_text(text)
    if key_length < 1:
        raise ValueError("key length must be positive")
    if len(cleaned) < key_length * 5:
        return None

    key: list[str] = []
    for offset in range(key_length):
        column = cleaned[offset::key_length]
        best_shift = max(range(26), key=lambda shift: letter_score(caesar_decode(column, shift)))
        # caesar_decode(column, shift) already subtracts the encryption shift,
        # so best_shift itself is the Vigenere key byte (not its inverse).
        key.append(chr(best_shift + ord("A")))
    return "".join(key)


def identify_cipher_type(text: str) -> str:
    cleaned = clean_text(text)
    if len(cleaned) < 2:
        return "Unknown"
    ic = index_of_coincidence(cleaned)
    if ic >= 0.055:
        return "Monalphabetic (Caesar or substitution likely)"
    return "Polyalphabetic (Vigenere possible)"


def substitution_frequency_report(text: str) -> list[str]:
    counts = Counter(clean_text(text))
    ordered = [letter for letter, _ in counts.most_common()]
    return [
        f"{cipher_letter} -> {ENGLISH_ORDER[index]}"
        for index, cipher_letter in enumerate(ordered[: len(ENGLISH_ORDER)])
    ]


def resolve_input(args: argparse.Namespace) -> str:
    supplied = [args.input is not None, args.text is not None, args.file is not None]
    if sum(supplied) != 1:
        raise CipherError("provide exactly one INPUT, --text VALUE, or --file PATH")
    if args.file is not None:
        path = Path(args.file).expanduser()
        if not path.is_file():
            raise CipherError(f"input file '{path}' was not found")
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CipherError(f"cannot read '{path}': {exc}") from exc
    if args.text is not None:
        return args.text
    value = args.input
    assert value is not None
    path = Path(value).expanduser()
    if path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CipherError(f"cannot read '{path}': {exc}") from exc
    if path.exists():
        raise CipherError(f"input path '{path}' is not a regular file")
    return value


def _caesar_report(text: str, shift: int | None, top: int) -> str:
    if shift is not None:
        decoded = caesar_decode(text, shift)
        return f"Caesar shift {shift % 26}:\n{decoded}"
    lines = [f"Top {top} Caesar candidates:"]
    for candidate_shift, decoded, score in caesar_brute_force(text)[:top]:
        lines.extend(["", f"Shift {candidate_shift} (score: {score:.4f}):", decoded])
    return "\n".join(lines)


def solve_to_report(args: argparse.Namespace, text: str) -> str:
    if args.top < 1:
        raise CipherError("--top must be at least 1")
    if args.key_length is not None and args.key_length < 1:
        raise CipherError("--key-length must be at least 1")

    if args.cipher_type == "caesar":
        return _caesar_report(text, args.caesar_shift, args.top)

    if args.cipher_type == "vigenere":
        if args.key:
            return f"Vigenere key: {clean_text(args.key)}\nDecrypted:\n{vigenere_decrypt(text, args.key)}"
        key_length = args.key_length
        estimates = None
        if key_length is None:
            estimates = estimate_vigenere_key_length(text)
            if not estimates:
                raise CipherError("not enough text to estimate a Vigenere key length; provide --key-length")
            key_length = estimates[0][0]
        key = vigenere_frequency_solve(text, key_length)
        if key is None:
            raise CipherError("not enough text for Vigenere frequency analysis")
        lines = []
        if estimates:
            lines.append(
                "Estimated key lengths: "
                + ", ".join(f"{length} (IC {ic:.4f})" for length, ic in estimates[:3])
            )
        lines.extend([f"Detected key: {key}", "Decrypted:", vigenere_decrypt(text, key)])
        return "\n".join(lines)

    if args.cipher_type == "substitution":
        mappings = substitution_frequency_report(text)
        if not mappings:
            raise CipherError("input contains no ASCII letters")
        return "Frequency-based substitution suggestions:\n" + "\n".join(mappings)

    identified = identify_cipher_type(text)
    lines = [f"Identified pattern: {identified}", "", _caesar_report(text, args.caesar_shift, args.top)]
    estimates = estimate_vigenere_key_length(text)
    if estimates:
        lines.extend(
            [
                "",
                "Vigenere key-length candidates: "
                + ", ".join(f"{length} (IC {ic:.4f})" for length, ic in estimates[:3]),
            ]
        )
        key = vigenere_frequency_solve(text, estimates[0][0])
        if key:
            lines.extend([f"Vigenere candidate key: {key}", vigenere_decrypt(text, key)])
    lines.extend(["", "Substitution frequency hints:", *substitution_frequency_report(text)[:10]])
    return "\n".join(lines)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise CipherError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + ("" if report.endswith("\n") else "\n"), encoding="utf-8")
    print(f"Output written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze and solve classical ciphers", allow_abbrev=False)
    parser.add_argument("input", nargs="?", help="Ciphertext literal or existing file")
    parser.add_argument("--text", help="Explicit literal ciphertext")
    parser.add_argument("--file", help="Explicit ciphertext file")
    parser.add_argument(
        "-c",
        "--cipher-type",
        choices=["caesar", "vigenere", "substitution", "auto"],
        default="auto",
    )
    parser.add_argument("-k", "--key-length", type=int, help="Vigenere key length")
    parser.add_argument("--key", help="Known Vigenere key")
    parser.add_argument("--caesar-shift", type=int, help="Specific Caesar shift")
    parser.add_argument("-n", "--top", type=int, default=5, help="Number of Caesar candidates")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        text = resolve_input(args)
        if not clean_text(text):
            raise CipherError("input contains no ASCII letters")
        report = solve_to_report(args, text)
        write_report(report, args.output)
        return 0
    except (CipherError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
