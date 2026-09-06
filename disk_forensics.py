#!/usr/bin/env python3
"""Read-only filesystem image inspection using The Sleuth Kit."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Sequence


class DiskError(ValueError):
    """A user-facing disk forensics error."""


INSTALL = "sudo apt install sleuthkit"
ENTRY_RE = re.compile(r"^(?P<kind>[^\s]+)\s+(?P<deleted>\*\s+)?(?P<inode>\d+)(?:-[^:]*)?:\s*(?P<name>.*)$")


def run_tool(argv: Sequence[str], timeout: int = 60, binary: bool = False) -> tuple[bytes | str, str, int]:
    if shutil.which(argv[0]) is None:
        raise DiskError(f"{argv[0]} is not installed ({INSTALL})")
    try:
        result = subprocess.run(list(argv), capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise DiskError(f"{argv[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise DiskError(f"could not run {argv[0]}: {exc}") from exc
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    output: bytes | str = result.stdout if binary else result.stdout.decode("utf-8", errors="replace")
    return output, stderr, result.returncode


def filesystem_metadata(image: Path) -> str:
    output, error, status = run_tool(["fsstat", str(image)])
    if status != 0:
        raise DiskError(error or f"fsstat exited with status {status}")
    return str(output).strip()


def list_entries(image: Path) -> list[dict[str, object]]:
    output, error, status = run_tool(["fls", "-r", "-p", str(image)])
    if status != 0:
        raise DiskError(error or f"fls exited with status {status}")
    entries: list[dict[str, object]] = []
    for line in str(output).splitlines():
        match = ENTRY_RE.match(line)
        if not match:
            continue
        kind = match.group("kind")
        entries.append({
            "inode": int(match.group("inode")),
            "name": match.group("name").strip(),
            "deleted": bool(match.group("deleted")) or "*" in kind,
            "directory": kind.startswith("d/"),
            "raw": line,
        })
    return entries


def read_inode(image: Path, inode: int) -> bytes:
    output, error, status = run_tool(["icat", str(image), str(inode)], binary=True)
    if status != 0:
        raise DiskError(error or f"icat failed for inode {inode} with status {status}")
    assert isinstance(output, bytes)
    return output


def text_preview(data: bytes, limit: int = 4096) -> str | None:
    sample = data[:limit]
    text = sample.decode("utf-8", errors="replace")
    if not text:
        return None
    readable = sum(char.isprintable() or char in "\r\n\t" for char in text) / len(text)
    if readable < 0.80:
        return None
    cleaned = "".join(char if char.isprintable() or char in "\r\n\t" else f"\\x{ord(char):02x}" for char in text)
    return cleaned.rstrip()


def safe_name(name: str, inode: int) -> str:
    leaf = Path(name).name
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", leaf).strip(".")
    return f"{inode}_{cleaned or 'recovered.bin'}"


def extract_entries(image: Path, entries: Sequence[dict[str, object]], destination: Path, force: bool) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    if not destination.is_dir():
        raise DiskError(f"output path '{destination}' is not a directory")
    written: list[Path] = []
    for entry in entries:
        if entry["directory"] or str(entry["name"]).startswith("$"):
            continue
        target = destination / safe_name(str(entry["name"]), int(entry["inode"]))
        if target.exists() and not force:
            raise DiskError(f"output '{target}' exists; use --force to replace it")
        target.write_bytes(read_inode(image, int(entry["inode"])))
        written.append(target)
    return written


def render_report(image: Path, metadata: str, entries: Sequence[dict[str, object]], previews: bool) -> str:
    metadata_lines = metadata.splitlines()
    summary = metadata_lines[:]
    if "CONTENT INFORMATION" in metadata_lines:
        summary = metadata_lines[: metadata_lines.index("CONTENT INFORMATION")]
    lines = ["Disk image forensics", "=" * 60, f"Image: {image}", "", "Filesystem:", *summary, "Entries:"]
    for entry in entries:
        state = "DELETED" if entry["deleted"] else "allocated"
        kind = "directory" if entry["directory"] else "file"
        lines.append(f"  inode {entry['inode']}: {entry['name']} [{kind}, {state}]")
        if previews and not entry["directory"] and not str(entry["name"]).startswith("$"):
            try:
                preview = text_preview(read_inode(image, int(entry["inode"])))
            except DiskError as exc:
                lines.append(f"    preview error: {exc}")
                continue
            if preview:
                shown = preview[:1000].replace("\n", "\n    ")
                lines.append(f"    preview: {shown}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect filesystem images without mounting them", allow_abbrev=False)
    parser.add_argument("image", help="Filesystem image")
    parser.add_argument("--preview", action="store_true", help="Show bounded readable previews, including deleted files")
    parser.add_argument("--extract-dir", help="Explicitly recover listed files into this directory")
    parser.add_argument("--force", action="store_true", help="Replace colliding recovered files")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        image = Path(args.image).expanduser()
        if not image.is_file():
            raise DiskError(f"image '{image}' was not found or is not a regular file")
        image = image.resolve()
        metadata = filesystem_metadata(image)
        entries = list_entries(image)
        report = render_report(image, metadata, entries, args.preview)
        if args.extract_dir:
            recovered = extract_entries(image, entries, Path(args.extract_dir).expanduser().resolve(), args.force)
            report += f"\n\nRecovered files: {len(recovered)}\n" + "\n".join(f"  {path}" for path in recovered)
        if args.output == "console":
            print(report)
        else:
            output = Path(args.output).expanduser()
            if not output.parent.exists():
                raise DiskError(f"output directory '{output.parent}' does not exist")
            output.write_text(report + "\n", encoding="utf-8")
            print(f"Report written to {output}")
        return 0
    except (DiskError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
