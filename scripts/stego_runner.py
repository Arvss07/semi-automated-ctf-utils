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
        return ["steghide", "stegseek", "zsteg"] if requested == "all" else [requested]
    lowered = (file_type or "").lower()
    if "jpeg" in lowered or suffix in {".jpg", ".jpeg"}:
        return ["steghide", "stegseek"]
    if "png" in lowered or suffix == ".png":
        return ["zsteg"]
    if "bitmap" in lowered or "bmp" in lowered or suffix == ".bmp":
        return ["zsteg", "steghide", "stegseek"]
    return ["steghide", "stegseek", "zsteg"]


def render_payload(path: Path, limit: int = 4096) -> str:
    data = path.read_bytes()
    preview = data[:limit]
    try:
        text = preview.decode("utf-8")
        printable = all(character.isprintable() or character in "\r\n\t" for character in text)
    except UnicodeDecodeError:
        printable = False
        text = ""
    rendered = text if printable else f"hex:{preview.hex()}"
    if len(data) > limit:
        rendered += f"\n... ({len(data) - limit} more bytes)"
    return rendered


def render_report(carrier: Path, file_type: str | None, attempts: list[Attempt]) -> str:
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
            lines.append(render_payload(attempt.payload))
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
    parser.add_argument("-t", "--tool", choices=["auto", "all", "steghide", "stegseek", "zsteg"], default="auto")
    parser.add_argument("--force", action="store_true", help="Allow an existing payload path to be overwritten")
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
            if tool == "steghide":
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
            if attempt.success:
                break

        report = render_report(carrier, file_type, attempts)
        write_report(report, args.output)
        return 0 if any(attempt.success for attempt in attempts) else 2
    except (StegoError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
