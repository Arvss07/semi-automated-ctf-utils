#!/usr/bin/env python3
"""Read-only SQLite schema, row, and recoverable-string inspection."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sqlite3
import sys
from typing import Sequence


class SQLiteError(ValueError):
    """A user-facing SQLite forensics error."""


def quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def open_read_only(path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        connection.execute("PRAGMA query_only = ON")
        return connection
    except sqlite3.Error as exc:
        raise SQLiteError(f"could not open SQLite database read-only: {exc}") from exc


def printable_runs(data: bytes, minimum: int = 6) -> list[str]:
    pattern = rb"[\x20-\x7e]{" + str(minimum).encode("ascii") + rb",}"
    seen: set[str] = set()
    strings: list[str] = []
    for match in re.findall(pattern, data):
        text = match.decode("ascii", errors="replace")
        if text not in seen:
            seen.add(text)
            strings.append(text)
    return strings


def analyze_database(path: Path, row_limit: int, include_strings: bool) -> dict[str, object]:
    if row_limit < 0:
        raise SQLiteError("--row-limit must be non-negative")
    connection = open_read_only(path)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        freelist = connection.execute("PRAGMA freelist_count").fetchone()[0]
        objects = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        tables: list[dict[str, object]] = []
        for object_type, name, _, sql in objects:
            if object_type != "table":
                continue
            quoted = quote_identifier(name)
            count = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({quoted})")]
            rows = connection.execute(f"SELECT * FROM {quoted} LIMIT ?", (row_limit,)).fetchall()
            tables.append({"name": name, "sql": sql, "columns": columns, "count": count, "rows": rows})
    except sqlite3.Error as exc:
        raise SQLiteError(f"SQLite analysis failed: {exc}") from exc
    finally:
        connection.close()
    return {
        "path": str(path), "integrity": integrity, "journal": journal,
        "page_size": page_size, "freelist": freelist, "objects": objects,
        "tables": tables, "strings": printable_runs(path.read_bytes()) if include_strings else [],
    }


def render_value(value: object, limit: int = 500) -> str:
    if isinstance(value, bytes):
        rendered = "hex:" + value.hex()
    else:
        rendered = str(value)
    return rendered if len(rendered) <= limit else rendered[:limit] + f"... ({len(rendered)} chars)"


def render_report(result: dict[str, object]) -> str:
    lines = [
        "SQLite forensics", "=" * 60, f"Database: {result['path']}",
        f"Integrity: {result['integrity']}", f"Journal mode: {result['journal']}",
        f"Page size: {result['page_size']}", f"Freelist pages: {result['freelist']}", "", "Schema:",
    ]
    objects = result["objects"]
    if not objects:
        lines.append("  (no user objects)")
    for object_type, name, _, sql in objects:
        lines.append(f"  [{object_type}] {name}: {sql or '(no SQL definition)'}")
    lines.append("\nRows:")
    for table in result["tables"]:
        lines.append(f"  Table {table['name']}: {table['count']} row(s)")
        columns = table["columns"]
        for row in table["rows"]:
            values = ", ".join(f"{column}={render_value(value)!r}" for column, value in zip(columns, row))
            lines.append(f"    {values}")
        if table["count"] > len(table["rows"]):
            lines.append(f"    ... {table['count'] - len(table['rows'])} more row(s); raise --row-limit")
    strings = result["strings"]
    if strings:
        lines.extend(["", "Raw printable strings (may include deleted/free-page remnants):"])
        lines.extend(f"  {render_value(value)}" for value in strings)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect SQLite databases in read-only mode", allow_abbrev=False)
    parser.add_argument("database", help="SQLite database")
    parser.add_argument("--row-limit", type=int, default=50, help="Maximum rows shown per table")
    parser.add_argument("--strings", action="store_true", help="Include raw printable strings for free-page triage")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        path = Path(args.database).expanduser()
        if not path.is_file():
            raise SQLiteError(f"database '{path}' was not found or is not a regular file")
        path = path.resolve()
        result = analyze_database(path, args.row_limit, args.strings)
        report = render_report(result)
        if args.output == "console":
            print(report)
        else:
            output = Path(args.output).expanduser()
            if not output.parent.exists():
                raise SQLiteError(f"output directory '{output.parent}' does not exist")
            output.write_text(report + "\n", encoding="utf-8")
            print(f"Report written to {output}")
        return 0
    except (SQLiteError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
