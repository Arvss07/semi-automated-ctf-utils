#!/usr/bin/env python3
"""Safely decode common CTF encodings from literal text or files."""

from __future__ import annotations

import argparse
import base64
import binascii
from pathlib import Path
import re
import sys
from typing import Callable, Sequence
import urllib.parse


DECODING_ORDER = ("binary", "hex", "url", "base32", "base64")


class DecodeError(ValueError):
    """A user-facing input or decoding error."""


def _to_ascii(data: bytes | str) -> str | None:
    if isinstance(data, str):
        return data
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return None


def _without_whitespace(text: str) -> str:
    return re.sub(r"\s+", "", text)


def decode_base64(data: bytes | str) -> bytes | None:
    """Decode strict standard Base64, tolerating whitespace and omitted padding."""
    text = _to_ascii(data)
    if text is None:
        return None
    compact = _without_whitespace(text)
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
        return None
    if "=" in compact[:-2] or len(compact) % 4 == 1:
        return None
    padded = compact + "=" * ((-len(compact)) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def decode_base32(data: bytes | str) -> bytes | None:
    """Decode Base32, tolerating whitespace, case, and omitted padding."""
    text = _to_ascii(data)
    if text is None:
        return None
    compact = _without_whitespace(text).upper()
    if not compact or not re.fullmatch(r"[A-Z2-7]*={0,6}", compact):
        return None
    if "=" in compact[:-6]:
        return None
    padded = compact + "=" * ((-len(compact)) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError):
        return None


def decode_hex(data: bytes | str) -> bytes | None:
    """Decode hexadecimal text with optional whitespace and a 0x prefix."""
    text = _to_ascii(data)
    if text is None:
        return None
    compact = _without_whitespace(text)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def decode_binary(data: bytes | str) -> bytes | None:
    """Decode binary octets separated only by whitespace or underscores."""
    text = _to_ascii(data)
    if text is None or not re.fullmatch(r"[01\s_]+", text):
        return None
    compact = re.sub(r"[\s_]", "", text)
    if not compact or len(compact) % 8:
        return None
    try:
        return int(compact, 2).to_bytes(len(compact) // 8, byteorder="big")
    except (ValueError, OverflowError):
        return None


def decode_url(data: bytes | str) -> bytes | None:
    """Decode percent-encoded URL bytes."""
    text = _to_ascii(data)
    if text is None or not re.search(r"%[0-9A-Fa-f]{2}", text):
        return None
    try:
        decoded = urllib.parse.unquote_to_bytes(text)
    except (ValueError, UnicodeError):
        return None
    original = text.encode("ascii")
    return decoded if decoded != original else None


DECODERS: dict[str, Callable[[bytes | str], bytes | None]] = {
    "base64": decode_base64,
    "base32": decode_base32,
    "hex": decode_hex,
    "binary": decode_binary,
    "url": decode_url,
}


def _looks_like(text: str, encoding: str) -> bool:
    compact = _without_whitespace(text)
    if encoding == "binary":
        bits = re.sub(r"[\s_]", "", text)
        return bool(bits) and len(bits) % 8 == 0 and bool(re.fullmatch(r"[01\s_]+", text))
    if encoding == "hex":
        candidate = compact[2:] if compact.lower().startswith("0x") else compact
        return len(candidate) >= 2 and len(candidate) % 2 == 0 and bool(
            re.fullmatch(r"[0-9A-Fa-f]+", candidate)
        )
    if encoding == "url":
        return bool(re.search(r"%[0-9A-Fa-f]{2}", text))
    if encoding == "base32":
        return len(compact) >= 8 and bool(re.fullmatch(r"[A-Z2-7]*={0,6}", compact))
    if encoding == "base64":
        return (
            len(compact) >= 4
            and len(compact) % 4 != 1
            and bool(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact))
        )
    return False


def is_encoding_like(data_str: str) -> bool:
    """Return whether text has the complete shape of a supported encoding."""
    return any(_looks_like(data_str, encoding) for encoding in DECODING_ORDER)


def is_readable(data: bytes, threshold: float = 0.90) -> bool:
    """Require valid UTF-8 with predominantly printable characters."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return True
    readable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    return readable / len(text) >= threshold


def auto_decode_once(data: bytes) -> tuple[bytes, str] | None:
    """Choose a shape-matched decoder only when its output remains readable."""
    text = _to_ascii(data)
    if text is None:
        return None

    for encoding in DECODING_ORDER:
        if not _looks_like(text, encoding):
            continue
        decoded = DECODERS[encoding](data)
        if decoded is not None and decoded != data and is_readable(decoded):
            return decoded, encoding
    return None


def render_bytes(data: bytes) -> str:
    """Render readable UTF-8 directly and binary data losslessly as hex."""
    if is_readable(data):
        return data.decode("utf-8")
    return data.hex()


def decode_recursive(
    data: bytes | str,
    max_iterations: int = 50,
    verbose: bool = False,
) -> tuple[str, int]:
    """Decode nested encodings until the current value is readable plaintext."""
    current = data.encode("utf-8") if isinstance(data, str) else data
    iterations = 0

    while iterations < max_iterations:
        decoded = auto_decode_once(current)
        if decoded is None:
            break
        current, encoding = decoded
        iterations += 1
        if verbose:
            print(f"[{iterations}] {encoding} decode", file=sys.stderr)

    return render_bytes(current), iterations


def decode_single(data: bytes | str, encoding: str) -> str | None:
    """Decode one explicit encoding and render the resulting bytes safely."""
    decoder = DECODERS.get(encoding)
    if decoder is None:
        return None
    decoded = decoder(data)
    return render_bytes(decoded) if decoded is not None else None


def _preflight_output(output: str, sources: set[str], allow_overwrite: bool = False) -> Path:
    """Reject outputs that collide with any input or artifact unless forced."""
    path = Path(output).expanduser().resolve()
    if not path.parent.exists():
        raise DecodeError(f"output directory '{path.parent}' does not exist")
    try:
        resolved_output = str(path)
        for src in sources:
            src_resolved = str(Path(src).resolve())
            if resolved_output == src_resolved:
                raise DecodeError("output path must not overwrite an input file")
    except OSError:
        pass
    if path.exists() and not allow_overwrite:
        raise DecodeError(f"output path '{path}' already exists; use --force to overwrite")
    return path


def resolve_input(args: argparse.Namespace) -> tuple[bytes, Path | None]:
    supplied = [args.input is not None, args.text is not None, args.file is not None]
    if sum(supplied) != 1:
        raise DecodeError("provide exactly one INPUT, --text VALUE, or --file PATH")

    if args.file is not None:
        path = Path(args.file).expanduser()
        if not path.is_file():
            raise DecodeError(f"input file '{path}' was not found or is not a regular file")
        try:
            return path.read_bytes(), path.resolve()
        except OSError as exc:
            raise DecodeError(f"cannot read '{path}': {exc}") from exc

    if args.text is not None:
        return args.text.encode("utf-8"), None

    value = args.input
    assert value is not None
    path = Path(value).expanduser()
    if path.is_file():
        try:
            return path.read_bytes(), path.resolve()
        except OSError as exc:
            raise DecodeError(f"cannot read '{path}': {exc}") from exc
    if path.exists():
        raise DecodeError(f"input path '{path}' is not a regular file")
    return value.encode("utf-8"), None


def write_output(result: str, output: str, sources: set[str] | None = None, force: bool = False) -> None:
    if output == "console":
        print(result)
        return

    sources = sources or set()
    path = _preflight_output(output, sources, allow_overwrite=force)
    try:
        path.write_text(result + ("" if result.endswith("\n") else "\n"), encoding="utf-8")
    except OSError as exc:
        raise DecodeError(f"cannot write '{path}': {exc}") from exc
    print(f"Output written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decode Base64, Base32, hex, binary, and URL-encoded data",
        allow_abbrev=False,
    )
    parser.add_argument("input", nargs="?", help="Literal text or existing file")
    parser.add_argument("--text", help="Explicit literal input")
    parser.add_argument("--file", help="Explicit input file")
    parser.add_argument(
        "-d",
        "--decode",
        choices=["base64", "base32", "hex", "binary", "url", "auto"],
        default="auto",
        help="Encoding to decode (default: auto)",
    )
    parser.add_argument("-r", "--recursive", action="store_true", help="Decode nested encodings")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show decoding steps on stderr")
    parser.add_argument("--max-depth", type=int, default=50, help="Maximum recursive decoding depth")
    parser.add_argument("--output", default="console", help="Output file path (default: console)")
    parser.add_argument("--force", action="store_true", help="Allow overwriting an existing output file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.max_depth < 1:
            raise DecodeError("--max-depth must be at least 1")
        data, source_path = resolve_input(args)
        sources: set[str] = {str(source_path)} if source_path else set()

        if args.decode == "auto":
            if args.recursive:
                result, _ = decode_recursive(data, args.max_depth, args.verbose)
            else:
                decoded = auto_decode_once(data)
                if decoded is None:
                    result = render_bytes(data)
                else:
                    value, encoding = decoded
                    if args.verbose:
                        print(f"[1] {encoding} decode", file=sys.stderr)
                    result = render_bytes(value)
        else:
            decoded = DECODERS[args.decode](data)
            if decoded is None:
                raise DecodeError(f"input is not valid {args.decode}")
            result = render_bytes(decoded)

        write_output(result, args.output, sources=sources, force=args.force)
        return 0
    except DecodeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
