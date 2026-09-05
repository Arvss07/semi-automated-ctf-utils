#!/usr/bin/env python3
"""Non-destructive first-pass identification and routing for CTF files."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from typing import Sequence

try:
    from encoding_decoder import is_encoding_like
    from hash_wrapper import detect_hash_type
except ImportError:  # Support import as scripts.triage from the repository root.
    from scripts.encoding_decoder import is_encoding_like
    from scripts.hash_wrapper import detect_hash_type


FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"flag\[[^\]]+\]",
    r"CTF\{[^}]+\}",
    r"CTF\[[^\]]+\]",
    r"CSAW\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
]

TOOL_INSTALL = {
    "file": "sudo apt install file",
    "exiftool": "sudo apt install libimage-exiftool-perl",
    "binwalk": "sudo apt install binwalk",
    "strings": "sudo apt install binutils",
}

EXTENSION_TYPES = {
    ".jpg": ("jpeg",),
    ".jpeg": ("jpeg",),
    ".png": ("png",),
    ".gif": ("gif",),
    ".pdf": ("pdf",),
    ".zip": ("zip",),
    ".tar": ("tar archive",),
    ".gz": ("gzip",),
    ".bmp": ("bitmap", "bmp"),
    ".wav": ("wav", "wave audio"),
    ".mp3": ("mp3", "mpeg adts"),
    ".pcap": ("capture file", "pcap"),
    ".pcapng": ("capture file", "pcap-ng", "pcapng"),
}


class TriageError(ValueError):
    """A user-facing triage validation error."""


def run_command(cmd: Sequence[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a bounded external analysis command without a shell."""
    executable = cmd[0]
    if shutil.which(executable) is None:
        install = TOOL_INSTALL.get(executable, f"install '{executable}'")
        return "", f"{executable} is not installed ({install})", 127
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
        return "", f"{executable} timed out after {timeout}s", 124
    except OSError as exc:
        return "", f"could not run {executable}: {exc}", 1


def check_flag_format(text: str) -> list[str]:
    """Return matching flag strings in stable first-seen order."""
    flags: list[str] = []
    seen: set[str] = set()
    for pattern in FLAG_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match not in seen:
                seen.add(match)
                flags.append(match)
    return flags


def get_file_type(filepath: str) -> tuple[str | None, str | None]:
    stdout, stderr, code = run_command(["file", "--", filepath])
    if code == 0 and stdout.strip():
        return stdout.strip(), None
    return None, stderr.strip() or "file could not identify the input"


def get_exiftool_data(filepath: str) -> tuple[str | None, str | None]:
    stdout, stderr, code = run_command(["exiftool", "--", filepath])
    if code == 0:
        return stdout.strip() or None, None
    return None, stderr.strip() or "exiftool failed"


def run_binwalk(filepath: str, extract: bool = False) -> tuple[str | None, str | None]:
    command = ["binwalk"]
    if extract:
        command.append("-e")
    command.append(filepath)
    stdout, stderr, code = run_command(command)
    if code == 0:
        return stdout.strip() or None, None
    return None, stderr.strip() or "binwalk failed"


def get_strings(filepath: str, min_len: int = 4) -> tuple[str | None, str | None]:
    stdout, stderr, code = run_command(["strings", "-n", str(min_len), "--", filepath])
    if code == 0:
        return stdout.strip() or None, None
    return None, stderr.strip() or "strings failed"


def check_extension_mismatch(filepath: str, file_type: str | None) -> str | None:
    """Compare a known extension with the already-obtained magic description."""
    if not file_type:
        return None
    extension = Path(filepath).suffix.lower()
    expected = EXTENSION_TYPES.get(extension)
    if not expected:
        return None
    lowered = file_type.lower()
    if any(marker in lowered for marker in expected):
        return None
    return f"extension '{extension}' does not match actual type: {file_type}"


def read_text_sample(filepath: Path, max_bytes: int = 1_048_576) -> str | None:
    """Read a bounded text sample without discarding invalid bytes silently."""
    try:
        data = filepath.read_bytes()[:max_bytes]
    except OSError:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def detect_text_hash(text: str | None) -> str:
    if not text:
        return "unknown"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "unknown"
    detected = {detect_hash_type(line) for line in lines[:100]}
    detected.discard("unknown")
    return detected.pop() if len(detected) == 1 else "unknown"


def _tool_command(
    script_name: str,
    filepath: Path,
    *options: str,
    input_flag: str | None = None,
) -> str:
    script = Path(__file__).resolve().with_name(script_name)
    argv = ["python3", str(script), *options]
    if input_flag:
        argv.extend([input_flag, str(filepath)])
    else:
        argv.append(str(filepath))
    return shlex.join(argv)


def build_suggestions(
    filepath: Path,
    file_type: str | None,
    text_sample: str | None,
    hash_type: str,
) -> list[str]:
    """Build ordered, directly runnable next-step commands."""
    if hash_type != "unknown":
        return [
            _tool_command(
                "hash_wrapper.py",
                filepath,
                "--type",
                hash_type,
                input_flag="--file",
            )
        ]

    lowered = (file_type or "").lower()
    suffix = filepath.suffix.lower()

    if "pcap" in lowered or "capture file" in lowered or suffix in {".pcap", ".pcapng"}:
        return [_tool_command("pcap_forensics.py", filepath)]
    if "jpeg" in lowered or "png" in lowered or "bitmap" in lowered or suffix in {".jpg", ".jpeg", ".png", ".bmp"}:
        return [_tool_command("stego_runner.py", filepath)]
    if any(marker in lowered for marker in ("zip", "rar archive", "7-zip")) or suffix in {".zip", ".rar", ".7z"}:
        return [_tool_command("archive_cracker.py", filepath)]
    if any(marker in lowered for marker in ("wav", "wave audio", "mp3", "mpeg adts")) or suffix in {".wav", ".mp3"}:
        return [_tool_command("audio_forensics.py", filepath)]
    if "pdf" in lowered or suffix == ".pdf":
        return ["Inspect PDF metadata/objects, then run strings or a PDF extraction tool"]
    if text_sample is not None or "text" in lowered or "ascii" in lowered:
        first_line = next((line.strip() for line in (text_sample or "").splitlines() if line.strip()), "")
        if first_line and is_encoding_like(first_line):
            return [
                _tool_command(
                    "encoding_decoder.py",
                    filepath,
                    "--recursive",
                    input_flag="--file",
                )
            ]
        return [_tool_command("cipher_solver.py", filepath)]
    return ["No specialized route identified; inspect the verbose report manually"]


def analyze_file(filepath: str, extract: bool = False) -> dict[str, object]:
    """Run observational analyzers and return a structured result."""
    path = Path(filepath).expanduser()
    if not path.is_file():
        raise TriageError(f"file '{path}' was not found or is not a regular file")
    path = path.resolve()

    file_type, file_error = get_file_type(str(path))
    metadata, metadata_error = get_exiftool_data(str(path))
    binwalk, binwalk_error = run_binwalk(str(path), extract=extract)
    strings_output, strings_error = get_strings(str(path))
    text_sample = read_text_sample(path)
    hash_type = detect_text_hash(text_sample)

    combined_text = "\n".join(part for part in (text_sample, strings_output) if part)
    warnings = [
        error
        for error in (file_error, metadata_error, binwalk_error, strings_error)
        if error
    ]
    mismatch = check_extension_mismatch(str(path), file_type)
    if mismatch:
        warnings.insert(0, mismatch)

    return {
        "filepath": str(path),
        "filename": path.name,
        "file_type": file_type,
        "extension_mismatch": mismatch,
        "exiftool_data": metadata,
        "binwalk_results": binwalk,
        "strings": strings_output,
        "flags_found": check_flag_format(combined_text),
        "hash_type": hash_type,
        "suggestions": build_suggestions(path, file_type, text_sample, hash_type),
        "warnings": warnings,
        "binwalk_extracted": extract,
    }


def render_report(results: dict[str, object], verbose: bool = False) -> str:
    """Render one report used by both console and file output."""
    lines = [
        "=" * 60,
        "CTF TRIAGE",
        "=" * 60,
        f"File: {results['filepath']}",
        f"Type: {results['file_type'] or 'Unknown'}",
    ]

    if results["hash_type"] != "unknown":
        lines.append(f"Hash format: {results['hash_type']}")
    if results["binwalk_extracted"]:
        lines.append("Binwalk extraction: explicitly enabled")

    warnings = results["warnings"]
    if warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"  - {warning}" for warning in warnings)

    metadata = results["exiftool_data"]
    if metadata:
        metadata_lines = str(metadata).splitlines()
        if not verbose:
            metadata_lines = metadata_lines[:10]
        lines.extend(["", "Metadata:", *[f"  {line}" for line in metadata_lines]])

    binwalk = results["binwalk_results"]
    if binwalk:
        lines.extend(["", "Binwalk:", str(binwalk)])

    strings_output = results["strings"]
    if strings_output and verbose:
        lines.extend(["", "Strings:", str(strings_output)])

    flags = results["flags_found"]
    lines.extend(["", "Flags:"])
    if flags:
        lines.extend(f"  [!] {flag}" for flag in flags)
    else:
        lines.append("  None found")

    lines.extend(["", "Suggested next steps:"])
    lines.extend(f"  {index}. {suggestion}" for index, suggestion in enumerate(results["suggestions"], 1))
    return "\n".join(lines)


def print_suggestions(suggestions: Sequence[str]) -> None:
    """Compatibility helper for callers that only need route text."""
    print("Suggested next steps:")
    for index, suggestion in enumerate(suggestions, 1):
        print(f"{index}. {suggestion}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Non-destructive first-pass CTF file analysis")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("--output", default="console", help="Report output path (default: console)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Include full metadata and strings")
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Explicitly allow binwalk extraction (analysis is non-destructive by default)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results = analyze_file(args.file, extract=args.extract)
        report = render_report(results, verbose=args.verbose)
        if args.output == "console":
            print(report)
        else:
            output = Path(args.output).expanduser()
            if not output.parent.exists():
                raise TriageError(f"output directory '{output.parent}' does not exist")
            output.write_text(report + "\n", encoding="utf-8")
            print(f"Triage report written to {output}")
        return 0
    except (TriageError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
