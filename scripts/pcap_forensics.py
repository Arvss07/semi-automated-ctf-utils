#!/usr/bin/env python3
"""Explicit tshark-based PCAP analysis with stream reassembly and safe exports."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Sequence


FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"flag\[[^\]]+\]",
    r"CTF\{[^}]+\}",
    r"CTF\[[^\]]+\]",
    r"picoCTF\{[^}]+\}",
    r"H4G\{[^}]+\}",
]


class PcapError(ValueError):
    """A user-facing packet-analysis error."""


def run_command(cmd: Sequence[str], timeout: int = 120) -> tuple[str, str, int]:
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


def check_tshark() -> bool:
    return shutil.which("tshark") is not None


def _tshark(pcap_file: str, arguments: Sequence[str], timeout: int = 120) -> str:
    if not check_tshark():
        raise PcapError("tshark is not installed (sudo apt install tshark)")
    command = ["tshark", "-r", str(Path(pcap_file).resolve()), *arguments]
    stdout, stderr, code = run_command(command, timeout=timeout)
    if code != 0:
        raise PcapError(stderr.strip() or stdout.strip() or f"tshark exited with status {code}")
    return stdout


def list_conversations(pcap_file: str) -> str:
    return _tshark(pcap_file, ["-q", "-z", "conv,tcp"])


def list_endpoints(pcap_file: str) -> str:
    return _tshark(pcap_file, ["-q", "-z", "endpoints,ip"])


def extract_http_objects(
    pcap_file: str,
    output_dir: str = "http_objects",
    force: bool = False,
) -> tuple[list[str] | None, str | None]:
    if not check_tshark():
        return None, "tshark is not installed (sudo apt install tshark)"
    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    if not destination.is_dir():
        return None, f"'{destination}' is not a directory"
    existing = {entry.resolve() for entry in destination.iterdir()}
    if existing and not force:
        return None, f"output directory '{destination}' is not empty; use --force"

    try:
        _tshark(
            pcap_file,
            ["--export-objects", f"http,{destination.resolve()}"],
            timeout=300,
        )
    except PcapError as exc:
        return None, str(exc)
    created = [
        str(entry.resolve())
        for entry in sorted(destination.iterdir(), key=lambda path: path.name)
        if entry.resolve() not in existing
    ]
    return created, None


def _field_query(
    pcap_file: str,
    display_filter: str,
    fields: Sequence[str],
) -> tuple[str, str | None]:
    arguments = ["-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
    for field in fields:
        arguments.extend(["-e", field])
    try:
        return _tshark(pcap_file, arguments), None
    except PcapError as exc:
        return "", str(exc)


def extract_credentials_with_warnings(
    pcap_file: str,
) -> tuple[list[tuple[str, str, str]], list[str]]:
    credentials: list[tuple[str, str, str]] = []
    warnings: list[str] = []

    stdout, error = _field_query(
        pcap_file,
        "ftp.request.command",
        ["ftp.request.command", "ftp.request.arg"],
    )
    if error:
        warnings.append(f"FTP query: {error}")
    else:
        for line in stdout.splitlines():
            command, _, argument = line.partition("\t")
            command = command.strip().upper()
            argument = argument.strip()
            if command in {"USER", "PASS"} and argument:
                credentials.append(("FTP", command, argument))

    stdout, error = _field_query(
        pcap_file,
        "http.authorization",
        ["http.authorization"],
    )
    if error:
        warnings.append(f"HTTP authorization query: {error}")
    else:
        for value in stdout.splitlines():
            value = value.strip()
            if not value.lower().startswith("basic "):
                continue
            try:
                decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
            except (ValueError, UnicodeError):
                continue
            if ":" in decoded:
                username, password = decoded.split(":", 1)
                credentials.append(("HTTP Basic", username, password))

    stdout, error = _field_query(
        pcap_file,
        'http.request.method == "POST"',
        ["http.file_data"],
    )
    if error:
        warnings.append(f"HTTP POST query: {error}")
    else:
        for value in stdout.splitlines():
            if "password" in value.lower() or "passwd" in value.lower():
                credentials.append(("HTTP POST", "form data", value.strip()[:500]))

    stdout, error = _field_query(pcap_file, "telnet", ["telnet.response.argument"])
    if error:
        warnings.append(f"Telnet query: {error}")
    else:
        for value in stdout.splitlines():
            if value.strip():
                credentials.append(("Telnet", "data", value.strip()[:500]))
    return credentials, warnings


def extract_credentials(pcap_file: str) -> list[tuple[str, str, str]]:
    return extract_credentials_with_warnings(pcap_file)[0]


def follow_tcp_stream(pcap_file: str, stream_index: int) -> str:
    if stream_index < 0:
        raise PcapError("stream index must be non-negative")
    return _tshark(pcap_file, ["-q", "-z", f"follow,tcp,ascii,{stream_index}"], timeout=300)


def list_tcp_streams(pcap_file: str, max_streams: int = 100) -> list[int]:
    if max_streams < 1:
        raise PcapError("max streams must be at least 1")
    stdout = _tshark(pcap_file, ["-T", "fields", "-e", "tcp.stream"])
    streams: set[int] = set()
    for value in stdout.splitlines():
        value = value.strip()
        if value.isdigit():
            streams.add(int(value))
    return sorted(streams)[:max_streams]


def _find_flags(text: str) -> list[str]:
    flags: list[str] = []
    seen: set[str] = set()
    for pattern in FLAG_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match not in seen:
                seen.add(match)
                flags.append(match)
    return flags


def search_for_flags(pcap_file: str, max_streams: int = 100) -> list[str]:
    """Search reassembled TCP streams rather than packet-local data fields."""
    flags: list[str] = []
    seen: set[str] = set()
    for stream in list_tcp_streams(pcap_file, max_streams=max_streams):
        content = follow_tcp_stream(pcap_file, stream)
        for flag in _find_flags(content):
            if flag not in seen:
                seen.add(flag)
                flags.append(flag)
    return flags


def analyze_pcap(pcap_file: str, max_streams: int = 100) -> dict[str, object]:
    if not check_tshark():
        raise PcapError("tshark is not installed (sudo apt install tshark)")
    results: dict[str, object] = {
        "pcap_file": str(Path(pcap_file).resolve()),
        "file_type": None,
        "conversations": None,
        "endpoints": None,
        "http_objects": None,
        "credentials": [],
        "flags": [],
        "warnings": [],
    }
    if shutil.which("file"):
        stdout, stderr, code = run_command(["file", "--", str(Path(pcap_file).resolve())], timeout=30)
        if code == 0:
            results["file_type"] = stdout.strip()
        elif stderr.strip():
            results["warnings"].append(stderr.strip())

    results["endpoints"] = list_endpoints(pcap_file)
    results["conversations"] = list_conversations(pcap_file)
    credentials, warnings = extract_credentials_with_warnings(pcap_file)
    results["credentials"] = credentials
    results["warnings"].extend(warnings)
    results["flags"] = search_for_flags(pcap_file, max_streams=max_streams)
    return results


def render_full_report(results: dict[str, object]) -> str:
    lines = [
        "PCAP Analysis",
        "=" * 60,
        f"File: {results['pcap_file']}",
        f"Type: {results['file_type'] or 'Unknown'}",
        "",
        "Endpoints:",
        str(results["endpoints"] or "None").strip(),
        "",
        "TCP Conversations:",
        str(results["conversations"] or "None").strip(),
        "",
        "Credentials:",
    ]
    credentials = results["credentials"]
    if credentials:
        for protocol, label, value in credentials:
            lines.append(f"  {protocol} {label}: {value}")
    else:
        lines.append("  None found")
    lines.append("")
    lines.append("Flags:")
    flags = results["flags"]
    lines.extend(f"  {flag}" for flag in flags) if flags else lines.append("  None found")
    if results["warnings"]:
        lines.extend(["", "Warnings:"])
        lines.extend(f"  - {warning}" for warning in results["warnings"])
    return "\n".join(lines)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise PcapError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + ("" if report.endswith("\n") else "\n"), encoding="utf-8")
    print(f"Report written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze PCAP files with tshark", allow_abbrev=False)
    parser.add_argument("pcap_file", help="PCAP or PCAPNG file")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("-c", "--conversations", action="store_true", help="List TCP conversations only")
    modes.add_argument("-e", "--endpoints", action="store_true", help="List IP endpoints only")
    modes.add_argument("-x", "--extract", action="store_true", help="Explicitly export HTTP objects")
    modes.add_argument("--stream", type=int, help="Follow one TCP stream")
    parser.add_argument("-d", "--directory", default="http_objects", help="HTTP export directory")
    parser.add_argument("--force", action="store_true", help="Allow export into a non-empty directory")
    parser.add_argument("--max-streams", type=int, default=100, help="Maximum streams searched in full mode")
    parser.add_argument("--output", default="console", help="Text report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        capture = Path(args.pcap_file).expanduser()
        if not capture.is_file():
            raise PcapError(f"capture '{capture}' was not found")
        capture = capture.resolve()

        if args.conversations:
            report = list_conversations(str(capture)).strip()
        elif args.endpoints:
            report = list_endpoints(str(capture)).strip()
        elif args.extract:
            files, error = extract_http_objects(str(capture), args.directory, args.force)
            if error:
                raise PcapError(error)
            report = f"HTTP objects exported: {len(files or [])}\n" + "\n".join(files or [])
        elif args.stream is not None:
            report = follow_tcp_stream(str(capture), args.stream).strip()
        else:
            if args.max_streams < 1:
                raise PcapError("--max-streams must be at least 1")
            report = render_full_report(analyze_pcap(str(capture), args.max_streams))

        write_report(report, args.output)
        return 0
    except (PcapError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
