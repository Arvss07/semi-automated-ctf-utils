#!/usr/bin/env python3
"""Extract archive hashes, crack them through hash_wrapper, or unpack archives."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Sequence
import zipfile


TOOL_INSTALL = {
    "file": "sudo apt install file",
    "zip2john": "sudo apt install john",
    "rar2john": "sudo apt install john",
    "7z2john": "sudo apt install john",
    "unzip": "sudo apt install unzip",
    "unrar": "sudo apt install unrar",
    "7z": "sudo apt install p7zip-full",
}


class ArchiveError(ValueError):
    """A user-facing archive operation error."""


def tool_path(tool_name: str) -> str | None:
    found = shutil.which(tool_name)
    if found:
        return found
    john_path = Path("/usr/share/john") / tool_name
    return str(john_path) if john_path.is_file() else None


def check_tool(tool_name: str) -> bool:
    return tool_path(tool_name) is not None


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


def get_archive_type(filepath: str) -> str | None:
    executable = tool_path("file")
    if not executable:
        return None
    stdout, _, code = run_command([executable, "--", str(Path(filepath).resolve())], timeout=30)
    return stdout.strip() if code == 0 and stdout.strip() else None


def archive_kind(filepath: Path, file_type: str | None) -> str | None:
    lowered = (file_type or "").lower()
    suffix = filepath.suffix.lower()
    if "zip archive" in lowered or suffix == ".zip":
        return "zip"
    if "rar archive" in lowered or suffix == ".rar":
        return "rar"
    if "7-zip" in lowered or suffix == ".7z":
        return "7z"
    return None


def extract_archive_hash(filepath: str, kind: str) -> str:
    extractor_name = {"zip": "zip2john", "rar": "rar2john", "7z": "7z2john"}[kind]
    executable = tool_path(extractor_name)
    if not executable:
        raise ArchiveError(f"{extractor_name} is not installed ({TOOL_INSTALL[extractor_name]})")
    stdout, stderr, code = run_command([executable, str(Path(filepath).resolve())])
    if code != 0:
        raise ArchiveError(stderr.strip() or f"{extractor_name} exited with status {code}")
    if not stdout.strip():
        raise ArchiveError(f"{extractor_name} produced no crackable hash")
    return stdout.strip()


def extract_zip_hash(filepath: str) -> tuple[str | None, str | None]:
    try:
        return extract_archive_hash(filepath, "zip"), None
    except ArchiveError as exc:
        return None, str(exc)


def extract_rar_hash(filepath: str) -> tuple[str | None, str | None]:
    try:
        return extract_archive_hash(filepath, "rar"), None
    except ArchiveError as exc:
        return None, str(exc)


def extract_7z_hash(filepath: str) -> tuple[str | None, str | None]:
    try:
        return extract_archive_hash(filepath, "7z"), None
    except ArchiveError as exc:
        return None, str(exc)


def crack_archive(filepath: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> tuple[bool, str]:
    """Crack an archive through hash_wrapper and return its recovered lines."""
    archive = Path(filepath).expanduser().resolve()
    file_type = get_archive_type(str(archive))
    kind = archive_kind(archive, file_type)
    if not kind:
        return False, f"unsupported archive type: {file_type or archive.suffix or 'unknown'}"
    wordlist_path = Path(wordlist).expanduser()
    if not wordlist_path.is_file():
        return False, f"wordlist '{wordlist_path}' was not found"

    try:
        hash_output = extract_archive_hash(str(archive), kind)
    except ArchiveError as exc:
        return False, str(exc)

    wrapper = Path(__file__).resolve().with_name("hash_wrapper.py")
    if not wrapper.is_file():
        return False, f"hash_wrapper.py was not found at {wrapper}"

    session = re.sub(r"[^A-Za-z0-9_.-]", "-", f"archive-{archive.stem}")
    with tempfile.TemporaryDirectory(prefix="ctf-archive-") as temp_dir:
        hash_file = Path(temp_dir) / "archive.hash"
        result_file = Path(temp_dir) / "cracked.txt"
        hash_file.write_text(hash_output + "\n", encoding="utf-8")
        command = [
            sys.executable,
            str(wrapper),
            "--file",
            str(hash_file),
            "--wordlist",
            str(wordlist_path),
            "--auto",
            "--session",
            session,
            "--output",
            str(result_file),
        ]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
        except OSError as exc:
            return False, f"could not start hash wrapper: {exc}"

        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            return False, detail or f"hash wrapper exited with status {completed.returncode}"
        if not result_file.is_file() or not result_file.read_text(encoding="utf-8").strip():
            return False, "hash wrapper reported success without a recovered password"
        recovered = result_file.read_text(encoding="utf-8").strip()
        return True, recovered


def _prepare_output_directory(output_dir: str, force: bool) -> Path:
    path = Path(output_dir).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ArchiveError(f"output path '{path}' is not a directory")
    if any(path.iterdir()) and not force:
        raise ArchiveError(f"output directory '{path}' is not empty; use --force to permit existing entries")
    return path.resolve()


def _validate_zip_archive(archive: str, max_entries: int, max_bytes: int) -> None:
    try:
        with zipfile.ZipFile(archive) as handle:
            entries = handle.infolist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArchiveError(f"invalid ZIP archive: {exc}") from exc
    if len(entries) > max_entries:
        raise ArchiveError(f"ZIP contains {len(entries)} entries; limit is {max_entries}")
    total = 0
    for entry in entries:
        parts = Path(entry.filename.replace("\\", "/")).parts
        if entry.filename.startswith(("/", "\\")) or ".." in parts:
            raise ArchiveError(f"unsafe ZIP member path: {entry.filename!r}")
        if stat.S_ISLNK(entry.external_attr >> 16):
            raise ArchiveError(f"ZIP symlink members are not extracted: {entry.filename!r}")
        total += entry.file_size
        if total > max_bytes:
            raise ArchiveError(f"ZIP expands beyond {max_bytes} bytes; raise --max-total-bytes explicitly")
        if entry.file_size > 1_048_576 and entry.compress_size and entry.file_size / entry.compress_size > 1000:
            raise ArchiveError(f"suspicious compression ratio for ZIP member {entry.filename!r}")


def plain_extract(filepath: str, kind: str, output_dir: str = ".", force: bool = False, max_entries: int = 10_000, max_bytes: int = 1_073_741_824) -> str:
    archive = str(Path(filepath).resolve())
    if max_entries < 1 or max_bytes < 1:
        raise ArchiveError("extraction limits must be positive")
    if kind == "zip":
        _validate_zip_archive(archive, max_entries, max_bytes)
    destination = _prepare_output_directory(output_dir, force)
    if kind == "zip":
        name = "unzip"
        command = [name, "-o" if force else "-n", archive, "-d", str(destination)]
    elif kind == "rar":
        name = "unrar"
        command = [name, "x", "-o+" if force else "-o-", archive, str(destination)]
    else:
        name = "7z"
        command = [name, "x", archive, f"-o{destination}", "-aoa" if force else "-aos"]

    executable = tool_path(name)
    if not executable:
        raise ArchiveError(f"{name} is not installed ({TOOL_INSTALL[name]})")
    command[0] = executable
    stdout, stderr, code = run_command(command)
    if code != 0:
        raise ArchiveError(stderr.strip() or stdout.strip() or f"{name} exited with status {code}")
    return stdout.strip() or f"archive extracted to {destination}"


def plain_extract_zip(filepath: str, output_dir: str = ".") -> tuple[str | None, str | None]:
    try:
        return plain_extract(filepath, "zip", output_dir), None
    except ArchiveError as exc:
        return None, str(exc)


def plain_extract_rar(filepath: str, output_dir: str = ".") -> tuple[str | None, str | None]:
    try:
        return plain_extract(filepath, "rar", output_dir), None
    except ArchiveError as exc:
        return None, str(exc)


def plain_extract_7z(filepath: str, output_dir: str = ".") -> tuple[str | None, str | None]:
    try:
        return plain_extract(filepath, "7z", output_dir), None
    except ArchiveError as exc:
        return None, str(exc)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise ArchiveError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + ("" if report.endswith("\n") else "\n"), encoding="utf-8")
    print(f"Report written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Crack or extract zip, rar, and 7z archives", allow_abbrev=False)
    parser.add_argument("file", help="Archive file")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt")
    parser.add_argument("-x", "--extract", action="store_true", help="Extract without cracking")
    parser.add_argument("--auto", action="store_true", help="Try cracking, then plain extraction if cracking fails")
    parser.add_argument("--output-dir", default=".", help="Extraction destination")
    parser.add_argument("--force", action="store_true", help="Permit existing output entries/overwrites")
    parser.add_argument("--max-entries", type=int, default=10_000, help="Maximum ZIP members to extract")
    parser.add_argument("--max-total-bytes", type=int, default=1_073_741_824, help="Maximum declared ZIP expansion")
    parser.add_argument("-o", "--output", default="console", help="Text report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        archive = Path(args.file).expanduser()
        if not archive.is_file():
            raise ArchiveError(f"archive '{archive}' was not found or is not a regular file")
        archive = archive.resolve()
        file_type = get_archive_type(str(archive))
        kind = archive_kind(archive, file_type)
        if not kind:
            raise ArchiveError(f"unsupported archive type: {file_type or archive.suffix or 'unknown'}")

        header = f"Archive: {archive}\nType: {file_type or kind}"
        if args.extract:
            detail = plain_extract(str(archive), kind, args.output_dir, args.force, args.max_entries, args.max_total_bytes)
            write_report(f"{header}\nStatus: extracted\n{detail}", args.output)
            return 0

        cracked, detail = crack_archive(str(archive), args.wordlist)
        if cracked:
            write_report(f"{header}\nStatus: password recovered\n{detail}", args.output)
            return 0

        if args.auto:
            extraction = plain_extract(str(archive), kind, args.output_dir, args.force, args.max_entries, args.max_total_bytes)
            write_report(
                f"{header}\nCracking failed: {detail}\nStatus: plain extraction attempted\n{extraction}",
                args.output,
            )
            return 0

        write_report(f"{header}\nStatus: cracking failed\n{detail}", args.output)
        return 2
    except (ArchiveError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
