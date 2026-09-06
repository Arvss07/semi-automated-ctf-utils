#!/usr/bin/env python3
"""Find strict-majority hash or size outliers in a batch of files."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from pathlib import Path
import sys
from typing import Iterable, Sequence


class BatchError(ValueError):
    """A user-facing batch analysis error."""


def sha256_file(filepath: str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(filepath, "rb") as handle:
            for chunk in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def get_file_size(filepath: str) -> int | None:
    try:
        return Path(filepath).stat().st_size
    except OSError:
        return None


def _normalize_extensions(extensions: Sequence[str] | None) -> set[str] | None:
    if not extensions:
        return None
    return {extension.lower() if extension.startswith(".") else f".{extension.lower()}" for extension in extensions}


def list_files(directory: str, extensions: Sequence[str] | None = None, recursive: bool = False) -> list[str]:
    path = Path(directory).expanduser()
    if not path.is_dir():
        raise BatchError(f"directory '{path}' was not found")
    allowed = _normalize_extensions(extensions)
    entries = path.rglob("*") if recursive else path.iterdir()
    return [
        str(entry.resolve())
        for entry in sorted(entries, key=lambda item: str(item.relative_to(path)))
        if entry.is_file() and (allowed is None or entry.suffix.lower() in allowed)
    ]


def collect_data(files: Sequence[str]) -> dict[str, dict[str, object]]:
    data: dict[str, dict[str, object]] = {}
    for filepath in files:
        path = Path(filepath).expanduser()
        if not path.is_file():
            raise BatchError(f"file '{path}' was not found or is not a regular file")
        resolved = str(path.resolve())
        file_hash = sha256_file(resolved)
        file_size = get_file_size(resolved)
        if file_hash is None or file_size is None:
            raise BatchError(f"could not read '{path}'")
        data[resolved] = {"hash": file_hash, "size": file_size, "name": path.name}
    return data


def _strict_majority(values: Iterable[object]) -> tuple[object | None, str]:
    items = list(values)
    if not items:
        return None, "empty"
    counts = Counter(items)
    if len(counts) == 1:
        return items[0], "unanimous"
    ranked = counts.most_common()
    top_value, top_count = ranked[0]
    tied = len(ranked) > 1 and ranked[1][1] == top_count
    if not tied and top_count > len(items) / 2:
        return top_value, "majority"
    return None, "ambiguous"


def analyze_files(
    files: Sequence[str], method: str = "both"
) -> tuple[list[str], dict[str, dict[str, object]], str, str]:
    data = collect_data(files)
    if not data:
        raise BatchError("no files to analyze")

    def assess(field: str) -> tuple[list[str], str]:
        majority, status = _strict_majority(item[field] for item in data.values())
        if status == "majority":
            return [path for path, item in data.items() if item[field] != majority], status
        return [], status

    if method == "hash":
        outliers, status = assess("hash")
        return outliers, data, "hash", status
    if method == "size":
        outliers, status = assess("size")
        return outliers, data, "size", status

    hash_outliers, hash_status = assess("hash")
    if hash_outliers:
        return hash_outliers, data, "hash", hash_status
    if hash_status == "unanimous":
        return [], data, "hash", "unanimous"

    size_outliers, size_status = assess("size")
    return size_outliers, data, "size", size_status


def find_outliers(
    directory: str, extensions: Sequence[str] | None = None
) -> tuple[list[str], list[str], list[str], dict[str, dict[str, object]]]:
    """Compatibility helper returning hash and size strict-majority outliers."""
    files = list_files(directory, extensions)
    if not files:
        return [], [], [], {}
    data = collect_data(files)
    hash_majority, hash_status = _strict_majority(item["hash"] for item in data.values())
    size_majority, size_status = _strict_majority(item["size"] for item in data.values())
    hash_outliers = (
        [path for path, item in data.items() if item["hash"] != hash_majority]
        if hash_status == "majority"
        else []
    )
    size_outliers = (
        [path for path, item in data.items() if item["size"] != size_majority]
        if size_status == "majority"
        else []
    )
    return files, hash_outliers, size_outliers, data


def find_outliers_simple(
    files: Sequence[str], by_hash: bool = True
) -> tuple[list[str], dict[str, dict[str, object]], str]:
    field = "hash" if by_hash else "size"
    data = collect_data(files)
    majority, status = _strict_majority(item[field] for item in data.values())
    outliers = (
        [path for path, item in data.items() if item[field] != majority]
        if status == "majority"
        else []
    )
    return outliers, data, field


def render_report(
    files: Sequence[str],
    outliers: Sequence[str],
    data: dict[str, dict[str, object]],
    method: str,
    status: str,
) -> str:
    lines = [
        "Batch Analysis",
        "=" * 60,
        f"Method: {method}",
        f"Decision: {status}",
        f"Total files: {len(files)}",
    ]
    if outliers:
        lines.append(f"Outliers found: {len(outliers)}")
    elif status == "ambiguous":
        lines.append("No strict majority exists; refusing to guess an outlier.")
    else:
        lines.append("No outliers found.")

    lines.extend(["", "File details:"])
    outlier_set = set(outliers)
    for filepath in sorted(files, key=lambda path: str(data[path]["name"])):
        item = data[filepath]
        marker = " [OUTLIER]" if filepath in outlier_set else ""
        lines.append(f"{item['name']}{marker}")
        lines.append(f"  Path: {filepath}")
        lines.append(f"  Size: {item['size']} bytes")
        lines.append(f"  SHA256: {item['hash']}")
    return "\n".join(lines)


def print_results(
    files: Sequence[str], outliers: Sequence[str], data: dict[str, dict[str, object]], method: str
) -> None:
    print(render_report(files, outliers, data, method, "majority" if outliers else "unanimous"))


def resolve_files(args: argparse.Namespace) -> list[str]:
    inputs = list(args.inputs)
    if args.file:
        inputs.extend(args.file)
    if not inputs:
        raise BatchError("no files or directory supplied")

    allowed = _normalize_extensions(args.ext)
    if len(inputs) == 1 and Path(inputs[0]).expanduser().is_dir():
        files = list_files(inputs[0], args.ext, args.recursive)
    else:
        files = []
        for value in inputs:
            path = Path(value).expanduser()
            if path.is_dir():
                raise BatchError("a directory can only be used as the sole input")
            if allowed is None or path.suffix.lower() in allowed:
                files.append(str(path.resolve()))
    if not files:
        raise BatchError("no files to analyze")
    return files


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise BatchError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + "\n", encoding="utf-8")
    print(f"Report written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Find strict-majority outlier files", allow_abbrev=False)
    parser.add_argument("inputs", nargs="*", help="One directory or two or more files")
    parser.add_argument("-f", "--file", nargs="+", help="Additional explicit files (compatibility option)")
    parser.add_argument("-e", "--ext", nargs="+", help="Extensions to include")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recurse when the sole input is a directory")
    parser.add_argument("-m", "--method", choices=["hash", "size", "both"], default="both")
    parser.add_argument("-o", "--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        files = resolve_files(args)
        outliers, data, method, status = analyze_files(files, args.method)
        write_report(render_report(files, outliers, data, method, status), args.output)
        return 0 if status != "ambiguous" else 2
    except (BatchError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
