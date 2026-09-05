#!/usr/bin/env python3
"""Generate deterministic demo fixtures for the CTF toolkit."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEMO_DIR = ROOT / "demo_files"


def ensure_dir(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def create_base64_demo(output_dir: Path = DEFAULT_DEMO_DIR) -> None:
    ensure_dir(output_dir)
    (output_dir / "base64_demo.txt").write_text(
        base64.b64encode(b"flag{base64_is_easy}").decode("ascii"), encoding="utf-8"
    )
    nested = b"flag{nested_base64}"
    for _ in range(3):
        nested = base64.b64encode(nested)
    (output_dir / "nested_base64_demo.txt").write_bytes(nested)


def create_caesar_demo(output_dir: Path = DEFAULT_DEMO_DIR) -> None:
    plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    shift = 13
    encrypted = "".join(
        chr((ord(character) - ord("A") + shift) % 26 + ord("A"))
        if "A" <= character <= "Z"
        else character
        for character in plaintext
    )
    (output_dir / "caesar_demo.txt").write_text(encrypted, encoding="utf-8")


def create_xor_demo(output_dir: Path = DEFAULT_DEMO_DIR) -> None:
    plaintext = b"flag{xor_repeating_key}"
    key = b"KEY"
    encrypted = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plaintext))
    (output_dir / "xor_demo.bin").write_bytes(encrypted)


def create_vigenere_demo(output_dir: Path = DEFAULT_DEMO_DIR) -> None:
    plaintext = (
        "THIS IS A LONG ENGLISH MESSAGE WITH COMMON WORDS AND LETTER FREQUENCIES "
        "DESIGNED TO DEMONSTRATE VIGENERE KEY RECOVERY IN THE CTF TOOLKIT"
    )
    key = "SECRET"
    encrypted: list[str] = []
    key_index = 0
    for character in plaintext:
        if "A" <= character <= "Z":
            shift = ord(key[key_index % len(key)]) - ord("A")
            encrypted.append(chr((ord(character) - ord("A") + shift) % 26 + ord("A")))
            key_index += 1
        else:
            encrypted.append(character)
    (output_dir / "vigenere_demo.txt").write_text("".join(encrypted), encoding="utf-8")


def create_flag_files(output_dir: Path = DEFAULT_DEMO_DIR) -> None:
    (output_dir / "hex_flag.txt").write_text(
        "666c61677b6865785f656e636f64696e677d", encoding="utf-8"
    )
    binary = "".join(format(byte, "08b") for byte in b"flag{binary_encode}")
    (output_dir / "binary_flag.txt").write_text(binary, encoding="utf-8")


def create_batch_files(output_dir: Path = DEFAULT_DEMO_DIR) -> None:
    batch_dir = ensure_dir(output_dir / "batch_test")
    for index in range(10):
        (batch_dir / f"file_{index:02d}.txt").write_text(
            f"NORMAL {index}\n" + "x" * 100, encoding="utf-8"
        )
    (batch_dir / "file_10.txt").write_text("OUTLIER\n" + "y" * 200, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate known-answer CTF demo files")
    parser.add_argument("--output-dir", default=str(DEFAULT_DEMO_DIR), help="Demo fixture directory")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = ensure_dir(Path(args.output_dir).expanduser())
    create_base64_demo(output_dir)
    create_caesar_demo(output_dir)
    create_xor_demo(output_dir)
    create_vigenere_demo(output_dir)
    create_flag_files(output_dir)
    create_batch_files(output_dir)
    print(f"Created deterministic CTF demo files in {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
