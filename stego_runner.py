#!/usr/bin/env python3
"""Safely orchestrate steghide, stegseek, and zsteg for CTF carriers."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


TOOL_INSTALL = {
    "file": "sudo apt install file",
    "steghide": "sudo apt install steghide",
    "stegseek": "install stegseek from https://github.com/RickdeJager/stegseek/releases",
    "zsteg": "gem install zsteg",
}


class StegoError(ValueError):
    """A user-facing steganography adapter error."""


@dataclass
class Attempt:
    tool: str
    success: bool
    detail: str
    payload: Path | None = None


def check_tool(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def run_command(cmd: Sequence[str], timeout: int = 300) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"{cmd[0]} timed out after {timeout}s", 124
    except OSError as exc:
        return "", f"could not run {cmd[0]}: {exc}", 1


def get_file_type(filepath: str) -> str | None:
    if not check_tool("file"):
        return None
    stdout, _, code = run_command(["file", "--", filepath], timeout=30)
    return stdout.strip() if code == 0 and stdout.strip() else None


def _missing_tool(tool: str) -> Attempt:
    return Attempt(tool, False, f"{tool} is not installed ({TOOL_INSTALL[tool]})")


def extract_steghide(
    filepath: str,
    output_path: str,
    passphrase: str = "",
    force: bool = False,
) -> Attempt:
    if not check_tool("steghide"):
        return _missing_tool("steghide")
    command = [
        "steghide",
        "extract",
        "-sf",
        str(Path(filepath).resolve()),
        "-p",
        passphrase,
        "-xf",
        output_path,
    ]
    if force:
        command.append("-f")
    stdout, stderr, code = run_command(command)
    target = Path(output_path)
    if code == 0 and target.is_file():
        return Attempt("steghide", True, stdout.strip() or "payload extracted", target)
    detail = stderr.strip() or stdout.strip() or f"steghide exited with status {code}"
    return Attempt("steghide", False, detail)


def extract_stegseek(
    filepath: str,
    wordlist: str,
    output_path: str,
    force: bool = False,
) -> Attempt:
    if not check_tool("stegseek"):
        return _missing_tool("stegseek")
    wordlist_path = Path(wordlist).expanduser()
    if not wordlist_path.is_file():
        return Attempt("stegseek", False, f"wordlist '{wordlist_path}' was not found")
    command = [
        "stegseek",
        "--crack",
        str(Path(filepath).resolve()),
        str(wordlist_path),
        output_path,
    ]
    if force:
        command.insert(2, "--force")
    stdout, stderr, code = run_command(command)
    target = Path(output_path)
    if code == 0 and target.is_file():
        return Attempt("stegseek", True, stdout.strip() or "payload extracted", target)
    detail = stderr.strip() or stdout.strip() or f"stegseek exited with status {code}"
    return Attempt("stegseek", False, detail)


def extract_zsteg(filepath: str) -> Attempt:
    if not check_tool("zsteg"):
        return _missing_tool("zsteg")
    stdout, stderr, code = run_command(["zsteg", str(Path(filepath).resolve()), "--all"])
    if code == 0 and stdout.strip():
        return Attempt("zsteg", True, stdout.strip())
    detail = stderr.strip() or stdout.strip() or f"zsteg exited with status {code}"
    return Attempt("zsteg", False, detail)


def run_steghide_extract(filepath: str, output_path: str | None = None) -> tuple[bytes | None, str | None]:
    """Compatibility helper using an explicit, non-guessed output path."""
    target = Path(output_path) if output_path else Path.cwd() / f"{Path(filepath).stem}.extracted"
    attempt = extract_steghide(filepath, str(target))
    if not attempt.success or not attempt.payload:
        return None, attempt.detail
    return attempt.payload.read_bytes(), None


def choose_tools(requested: str, file_type: str | None, suffix: str) -> list[str]:
    if requested != "auto":
        return ["native", "steghide", "stegseek", "zsteg"] if requested == "all" else [requested]
    lowered = (file_type or "").lower()
    if "jpeg" in lowered or suffix in {".jpg", ".jpeg"}:
        return ["native", "steghide", "stegseek"]
    if "png" in lowered or suffix == ".png":
        return ["native", "zsteg"]
    if "bitmap" in lowered or "bmp" in lowered or suffix == ".bmp":
        return ["native", "zsteg", "steghide", "stegseek"]
    return ["native", "steghide", "stegseek", "zsteg"]


FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"flag\[[^\]]+\]",
    r"CTF\{[^}]+\}",
    r"CTF\[[^\]]+\]",
    r"CSAW\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"H4G\{[^}]+\}",
]

WHITESPACE_ALPHABET = {0x20, 0x09, 0x0D, 0x0A}
ZERO_WIDTH_BITS = {"\u200b": "0", "\u200c": "1"}
APPENDED_SIGNATURES = {b"PK\x03\x04": "ZIP", b"Rar!\x1a\x07": "RAR", b"7z\xbc\xaf'\x1c": "7z", b"%PDF-": "PDF"}


def native_scan(filepath: str) -> Attempt:
    data = Path(filepath).read_bytes()
    details: list[str] = []
    text = data.decode("utf-8", errors="ignore")
    bits = "".join(ZERO_WIDTH_BITS[char] for char in text if char in ZERO_WIDTH_BITS)
    if len(bits) >= 8:
        decoded = bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits) - 7, 8))
        details.append(f"zero-width: {len(bits)} bits -> {render_bytes_preview(decoded)}")
    for signature, name in APPENDED_SIGNATURES.items():
        start = data.find(signature, 1)
        if start > 0:
            details.append(f"embedded/appended {name} signature at byte offset {start} (use binwalk for explicit carving)")
    return Attempt("native", bool(details), "; ".join(details) if details else "no zero-width or appended payload signature found")


def render_bytes_preview(data: bytes, limit: int = 240) -> str:
    sample = data[:limit]
    try:
        text = sample.decode("utf-8")
        if all(char.isprintable() or char in "\r\n\t" for char in text):
            return repr(text)
    except UnicodeDecodeError:
        pass
    return "hex:" + sample.hex() + ("..." if len(data) > limit else "")


def check_flag_format(data: bytes) -> list[str]:
    """Return flag strings found in bytes (UTF-8, errors ignored)."""
    import re as _re

    text = data.decode("utf-8", errors="ignore")
    flags: list[str] = []
    seen: set[str] = set()
    for pattern in FLAG_PATTERNS:
        for match in _re.findall(pattern, text, _re.IGNORECASE):
            if match not in seen:
                seen.add(match)
                flags.append(match)
    return flags


def is_whitespace_stego(data: bytes) -> bool:
    """Return True for snow-like payloads (only space/tab/CR/LF)."""
    if not data:
        return False
    if any(byte not in WHITESPACE_ALPHABET for byte in data):
        return False
    return 0x20 in data and 0x09 in data and (0x0A in data)


def whitespace_decode(payload: bytes) -> dict[str, bytes]:
    """Decode snow-like whitespace stego over line/bit/order variants."""
    results: dict[str, bytes] = {}
    for split_name, lines in (
        ("crlf", payload.split(b"\r\n")),
        ("lf", payload.split(b"\n")),
    ):
        if len(lines) < 2:
            continue
        for map_name, mapping in (
            ("sp0_tab1", {0x20: "0", 0x09: "1"}),
            ("sp1_tab0", {0x20: "1", 0x09: "0"}),
        ):
            bitstrs: list[str] = []
            ok = True
            for line in lines:
                if not line:
                    continue
                try:
                    bitstrs.append("".join(mapping[c] for c in line))
                except KeyError:
                    ok = False
                    break
            if not ok or not bitstrs:
                continue
            for order in ("msb", "lsb"):
                if all(len(bits) == 8 for bits in bitstrs):
                    out = bytearray()
                    for bits in bitstrs:
                        if order == "lsb":
                            bits = bits[::-1]
                        try:
                            out.append(int(bits, 2))
                        except ValueError:
                            out = bytearray()
                            break
                    else:
                        results[f"{split_name}/{map_name}/{order}/per-line"] = bytes(out)
                        continue
                raw_bits = "".join(bitstrs)
                bits = raw_bits if order == "msb" else raw_bits[::-1]
                if len(bits) >= 8:
                    try:
                        results[f"{split_name}/{map_name}/{order}/stream"] = bytes(
                            int(bits[i : i + 8], 2)
                            for i in range(0, len(bits) - len(bits) % 8, 8)
                        )
                    except ValueError:
                        continue
    return results


def is_readable_text(data: bytes, threshold: float = 0.90) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return True
    readable = sum(c.isprintable() or c in "\r\n\t" for c in text)
    return readable / len(text) >= threshold


def escaped_preview(data: bytes, limit: int = 200) -> str:
    """cat -A style preview so whitespace payloads are visible."""
    chunk = data[:limit]
    rendered = (
        chunk.decode("utf-8", errors="replace")
        .replace("\t", "^I")
        .replace("\r", "")
    )
    lines = rendered.split("\n")
    shown = "\n".join(f"{line}$" for line in lines[:8])
    if len(data) > limit or len(lines) > 8:
        shown += f"\n... ({len(data)} bytes total)"
    return shown


def render_payload(path: Path, limit: int = 4096, verbose: bool = False) -> str:
    data = path.read_bytes()
    preview = data[:limit]
    try:
        text = preview.decode("utf-8")
        printable = all(character.isprintable() or character in "\r\n\t" for character in text)
    except UnicodeDecodeError:
        printable = False
        text = ""
    chunks = [
        f"Size: {len(data)} bytes",
        f"Type: {get_file_type(str(path)) or 'unknown'}",
    ]
    flags = check_flag_format(data)
    if flags:
        chunks.append("Flags:")
        chunks.extend(f"  [!] {flag}" for flag in flags)
    else:
        chunks.append("Flags: none found")
    if is_whitespace_stego(data):
        lines = [line for line in data.split(b"\r\n") if line] or [
            line for line in data.split(b"\n") if line
        ]
        chunks.append(
            f"Whitespace stego: alphabet={{space,tab,CRLF}}, "
            f"{len(lines)} non-empty lines, {len(data)} bytes "
            f"(blank render is expected; see escaped preview)"
        )
        chunks.append("Escaped preview (cat -A style, ^I=tab, $=EOL):")
        chunks.append(escaped_preview(data))
        decoded = whitespace_decode(data)
        hits = {name: blob for name, blob in decoded.items() if check_flag_format(blob)}
        if hits:
            chunks.append(f"Whitespace decode: {len(hits)} variant(s) contain a flag:")
            for name, blob in hits.items():
                for flag in check_flag_format(blob):
                    chunks.append(f"  [!] {flag} (via {name})")
                decoded_text = blob.decode("utf-8", errors="replace")
                chunks.append(f"  Decoded ({name}): {decoded_text[:200]}")
        else:
            chunks.append(f"Whitespace decode: {len(decoded)} variant(s), no flag found")
        if verbose:
            for name, blob in sorted(decoded.items()):
                sample = blob.decode("utf-8", errors="replace")[:120]
                chunks.append(f"  - {name}: {sample!r}")
        elif decoded and not hits:
            # Show the most plausible (readable) candidate even without a flag.
            readable = [(n, b) for n, b in decoded.items() if is_readable_text(b)]
            if readable:
                name, blob = readable[0]
                chunks.append(f"  Top readable candidate ({name}): {blob.decode('utf-8', errors='replace')[:200]}")
        return "\n".join(chunks)
    rendered = text if printable else f"hex:{preview.hex()}"
    if len(data) > limit:
        rendered += f"\n... ({len(data) - limit} more bytes)"
    chunks.append("Payload preview:")
    chunks.append(rendered)
    return "\n".join(chunks)


def render_report(
    carrier: Path, file_type: str | None, attempts: list[Attempt], verbose: bool = False
) -> str:
    lines = [
        "Steganography analysis",
        "=" * 60,
        f"Carrier: {carrier}",
        f"Type: {file_type or 'Unknown (extension fallback used)'}",
        "",
        "Attempts:",
    ]
    for attempt in attempts:
        status = "SUCCESS" if attempt.success else "FAILED"
        lines.append(f"[{status}] {attempt.tool}: {attempt.detail}")
        if attempt.payload:
            lines.append(f"Payload: {attempt.payload}")
            lines.append(render_payload(attempt.payload, verbose=verbose))
    return "\n".join(lines)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise StegoError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + "\n", encoding="utf-8")
    print(f"Report written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract or analyze image steganography", allow_abbrev=False)
    parser.add_argument("file", help="Carrier image")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt")
    parser.add_argument("-p", "--passphrase", help="Passphrase for steghide")
    parser.add_argument("--extract-to", help="Exact payload destination")
    parser.add_argument("--output-dir", default=".", help="Default payload directory")
    parser.add_argument("-o", "--output", default="console", help="Text report output path")
    parser.add_argument("-t", "--tool", choices=["auto", "all", "native", "steghide", "stegseek", "zsteg"], default="auto")
    parser.add_argument("--force", action="store_true", help="Allow an existing payload path to be overwritten")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all whitespace-decode variants")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        carrier = Path(args.file).expanduser()
        if not carrier.is_file():
            raise StegoError(f"carrier '{carrier}' was not found or is not a regular file")
        carrier = carrier.resolve()

        output_dir = Path(args.output_dir).expanduser()
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = Path(args.extract_to).expanduser() if args.extract_to else output_dir / f"{carrier.stem}.extracted"
        if not payload.is_absolute():
            payload = payload.resolve()
        if payload.parent.exists() and payload.is_symlink():
            raise StegoError(f"payload path '{payload}' is a symlink; extraction to symlinks is not permitted")
        if not payload.parent.exists():
            raise StegoError(f"payload directory '{payload.parent}' does not exist")
        if payload.exists() and not args.force:
            raise StegoError(f"payload path '{payload}' already exists; use --force to replace it")

        file_type = get_file_type(str(carrier))
        tools = choose_tools(args.tool, file_type, carrier.suffix.lower())
        attempts: list[Attempt] = []
        for tool in tools:
            if tool == "native":
                attempt = native_scan(str(carrier))
            elif tool == "steghide":
                attempt = extract_steghide(
                    str(carrier),
                    str(payload),
                    args.passphrase or "",
                    args.force,
                )
            elif tool == "stegseek":
                attempt = extract_stegseek(
                    str(carrier),
                    args.wordlist,
                    str(payload),
                    args.force,
                )
            else:
                attempt = extract_zsteg(str(carrier))
            attempts.append(attempt)
            if attempt.success and args.tool != "all":
                break

        report = render_report(carrier, file_type, attempts, verbose=args.verbose)
        write_report(report, args.output)
        return 0 if any(attempt.success for attempt in attempts) else 2
    except (StegoError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
