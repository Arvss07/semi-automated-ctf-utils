#!/usr/bin/env python3
"""Read-only offline MySQL/MariaDB logical-dump inspection (no live connections)."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from typing import Sequence


class DumpError(ValueError):
    """A user-facing dump forensics error."""


MAX_DUMP_BYTES = 20_000_000

FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"flag\[[^\]]+\]",
    r"CTF\{[^}]+\}",
    r"CTF\[[^\]]+\}",
    r"CSAW\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"H4G\{[^}]+\}",
]

MYSQL_MARKERS = (
    "MySQL dump",
    "MariaDB dump",
    "mysqldump",
    "LOCK TABLES",
    "UNLOCK TABLES",
    "ENGINE=",
    "USING BTREE",
    "/*!40",
)


def quote_key(name: str) -> str:
    return name.strip().strip('"').strip("`").strip("'").strip("[]")


def split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    in_single = False
    in_double = False
    in_backtick = False
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if in_single:
            current.append(char)
            if char == "'" and text[index + 1 : index + 2] == "'":
                current.append("'")
                index += 1
            elif char == "'":
                in_single = False
            index += 1
            continue
        if in_double:
            current.append(char)
            if char == '"':
                in_double = False
            index += 1
            continue
        if in_backtick:
            current.append(char)
            if char == "`":
                in_backtick = False
            index += 1
            continue
        if char == "'":
            in_single = True
            current.append(char)
        elif char == '"':
            in_double = True
            current.append(char)
        elif char == "`":
            in_backtick = True
            current.append(char)
        elif char == "(":
            depth += 1
            current.append(char)
        elif char == ")":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def extract_balanced(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] != "(":
        return None
    depth = 0
    in_single = False
    in_double = False
    in_backtick = False
    index = start
    while index < len(text):
        char = text[index]
        if in_single:
            if char == "'" and text[index + 1 : index + 2] == "'":
                index += 2
                continue
            if char == "'":
                in_single = False
            index += 1
            continue
        if in_double:
            if char == '"':
                in_double = False
            index += 1
            continue
        if in_backtick:
            if char == "`":
                in_backtick = False
            index += 1
            continue
        if char == "'":
            in_single = True
        elif char == '"':
            in_double = True
        elif char == "`":
            in_backtick = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index], index + 1
        index += 1
    return None


def unwrap_mysql_conditionals(text: str) -> str:
    """Keep /*! ... */ inner SQL while dropping ordinary /* ... */ comments."""

    def replace(match: re.Match[str]) -> str:
        body = match.group(0)
        if body.startswith("/*!"):
            inner = body[3:-2]
            # Strip the leading version number (e.g. /*!40101 SET ... */).
            inner = re.sub(r"^\d+\s*", "", inner)
            return inner
        return ""

    return re.sub(r"/\*.*?\*/", replace, text, flags=re.DOTALL)


def parse_create_tables(sql: str) -> dict[str, dict[str, object]]:
    tables: dict[str, dict[str, object]] = {}
    pattern = re.compile(
        r"CREATE\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>[^\s(]+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(sql):
        raw_name = match.group("name").strip().rstrip(";")
        if raw_name.startswith(("-", "/")):
            continue
        name = raw_name.split(".")[-1]
        name = quote_key(name)
        if not name or name.startswith("("):
            continue
        paren_start = sql.find("(", match.end())
        if paren_start == -1:
            continue
        if ";" in sql[match.end() : paren_start]:
            continue
        extracted = extract_balanced(sql, paren_start)
        if extracted is None:
            continue
        inner, _ = extracted
        columns: list[str] = []
        for part in split_top_level(inner):
            token = part.strip()
            if not token:
                continue
            upper = token.upper()
            if upper.startswith(
                (
                    "CONSTRAINT",
                    "PRIMARY",
                    "FOREIGN",
                    "UNIQUE",
                    "CHECK",
                    "KEY ",
                    "INDEX",
                    "FULLTEXT",
                    "SPATIAL",
                    "PERIOD",
                )
            ):
                continue
            col = token.split()[0].strip().strip('"`[]')
            col = col.split(".")[-1].strip('"`[]')
            if col and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", col):
                columns.append(col)
        if name not in tables:
            tables[name] = {"columns": columns, "rows": [], "count": 0}
        elif not tables[name]["columns"] and columns:
            tables[name]["columns"] = columns
    return tables


def parse_value_token(token: str) -> str | None:
    token = token.strip()
    if not token or token.upper() == "NULL" or token == r"\N":
        return None
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1].replace("''", "'").replace("\\'", "'").replace("\\\\", "\\")
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return token


def parse_insert_values(values_text: str) -> list[list[str | None]]:
    rows: list[list[str | None]] = []
    index = 0
    while index < len(values_text):
        while index < len(values_text) and values_text[index] not in "(,":
            if values_text[index] == ";":
                return rows
            index += 1
        if index >= len(values_text) or values_text[index] != "(":
            index += 1
            continue
        extracted = extract_balanced(values_text, index)
        if extracted is None:
            break
        inner, next_index = extracted
        rows.append([parse_value_token(part) for part in split_top_level(inner)])
        index = next_index
    return rows


def parse_inserts(sql: str, tables: dict[str, dict[str, object]]) -> None:
    pattern = re.compile(
        r"INSERT\s+(?:IGNORE\s+)?INTO\s+(?P<name>[^\s(]+)(?:\s*\((?P<cols>[^)]+)\))?\s*VALUES\s*(?P<values>.*?);",
        re.IGNORECASE | re.DOTALL,
    )
    # MySQL also uses REPLACE INTO for dumps.
    replace_pattern = re.compile(
        r"REPLACE\s+INTO\s+(?P<name>[^\s(]+)(?:\s*\((?P<cols>[^)]+)\))?\s*VALUES\s*(?P<values>.*?);",
        re.IGNORECASE | re.DOTALL,
    )
    for active in (pattern, replace_pattern):
        for match in active.finditer(sql):
            raw_name = match.group("name").strip()
            name = quote_key(raw_name.split(".")[-1])
            if not name:
                continue
            cols_raw = match.group("cols")
            cols = [quote_key(part) for part in cols_raw.split(",")] if cols_raw else []
            entry = tables.setdefault(name, {"columns": [], "rows": [], "count": 0})
            if not entry["columns"] and cols:
                entry["columns"] = cols
            columns = list(entry["columns"]) or cols
            for values in parse_insert_values(match.group("values")):
                entry["count"] += 1  # type: ignore[typeddict-item]
                if len(entry["rows"]) < 10_000:
                    if columns and len(values) == len(columns):
                        entry["rows"].append(dict(zip(columns, values)))  # type: ignore[arg-type]
                    else:
                        entry["rows"].append({f"col{i+1}": value for i, value in enumerate(values)})


def find_flags(text: str) -> list[str]:
    flags: list[str] = []
    seen: set[str] = set()
    for pattern in FLAG_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match not in seen:
                seen.add(match)
                flags.append(match)
    return flags


def printable_runs(data: bytes, minimum: int = 6) -> list[str]:
    pattern = rb"[\x20-\x7e]{" + str(minimum).encode("ascii") + rb",}"
    seen: set[str] = set()
    ordered: list[str] = []
    for match in re.findall(pattern, data):
        text = match.decode("ascii", errors="replace")
        if text not in seen:
            seen.add(text)
            ordered.append(text)
    return ordered


def render_value(value: object, limit: int = 500) -> str:
    rendered = "NULL" if value is None else str(value)
    return rendered if len(rendered) <= limit else rendered[:limit] + f"... ({len(rendered)} chars)"


def analyze_dump(path: Path, row_limit: int, include_strings: bool) -> dict[str, object]:
    if row_limit < 0:
        raise DumpError("--row-limit must be non-negative")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DumpError(f"cannot read '{path}': {exc}") from exc
    if len(raw) > MAX_DUMP_BYTES:
        raise DumpError(f"dump is {len(raw)} bytes; v1 limit is {MAX_DUMP_BYTES} bytes")
    if raw[:5] == b"PGDMP":
        raise DumpError("PostgreSQL custom-format archive detected; convert first: pg_restore -f dump.sql dump.pgdump")
    if b"\x00" in raw[:8192] and len(raw) > 0:
        raise DumpError("binary dump detected; only plain-SQL text dumps are supported in v1")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DumpError(f"dump is not valid UTF-8 text: {exc}") from exc

    warnings: list[str] = []
    flavor = "generic-plain-sql"
    if any(marker in text for marker in MYSQL_MARKERS):
        flavor = "mysql"
    else:
        warnings.append("no MySQL/MariaDB markers found; showing generic plain-SQL parse")

    scrubbed = unwrap_mysql_conditionals(text)
    tables = parse_create_tables(scrubbed)
    parse_inserts(scrubbed, tables)

    total_rows = sum(int(entry["count"]) for entry in tables.values())
    if not tables:
        warnings.append("no CREATE TABLE / INSERT / REPLACE statements parsed")
    return {
        "path": str(path),
        "flavor": flavor,
        "size": len(raw),
        "tables": tables,
        "total_rows": total_rows,
        "flags": find_flags(text),
        "warnings": warnings,
        "strings": printable_runs(raw) if include_strings else [],
    }


def render_report(result: dict[str, object], row_limit: int) -> str:
    lines = [
        "MySQL dump forensics",
        "=" * 60,
        f"Dump: {result['path']}",
        f"Flavor: {result['flavor']}",
        f"Size: {result['size']} bytes, Tables: {len(result['tables'])}, Total rows: {result['total_rows']}",
    ]
    warnings = result["warnings"]
    if warnings:
        lines.extend(["", "Warnings:"])
        lines.extend(f"  - {warning}" for warning in warnings)
    tables = result["tables"]
    lines.extend(["", "Schema:"])
    if not tables:
        lines.append("  (no tables parsed)")
    for name in sorted(tables):
        columns = tables[name]["columns"]
        lines.append(f"  [table] {name}: {', '.join(columns) if columns else '(unknown columns)'}")
    lines.append("\nRows:")
    if not tables:
        lines.append("  (no rows)")
    for name in sorted(tables):
        entry = tables[name]
        lines.append(f"  Table {name}: {entry['count']} row(s)")
        for row in entry["rows"][:row_limit]:
            values = ", ".join(f"{column}={render_value(value)!r}" for column, value in row.items())
            lines.append(f"    {values}")
        if entry["count"] > len(entry["rows"][:row_limit]):
            lines.append(f"    ... {entry['count'] - len(entry['rows'][:row_limit])} more row(s); raise --row-limit")
    flags = result["flags"]
    lines.extend(["", "Flags:"])
    if flags:
        lines.extend(f"  [!] {flag}" for flag in flags)
    else:
        lines.append("  None found")
    strings = result["strings"]
    if strings:
        lines.extend(["", "Raw printable strings (bounded, may repeat row text):"])
        lines.extend(f"  {render_value(value)}" for value in strings[:200])
        if len(strings) > 200:
            lines.append(f"  ... {len(strings) - 200} more string(s)")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect offline MySQL/MariaDB logical dumps without a live server",
        allow_abbrev=False,
    )
    parser.add_argument("dump", help="Logical dump file (.sql)")
    parser.add_argument("--row-limit", type=int, default=50, help="Maximum rows shown per table")
    parser.add_argument("--strings", action="store_true", help="Include raw printable strings")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        path = Path(args.dump).expanduser()
        if not path.is_file():
            raise DumpError(f"dump '{path}' was not found or is not a regular file")
        result = analyze_dump(path.resolve(), args.row_limit, args.strings)
        report = render_report(result, args.row_limit)
        if args.output == "console":
            print(report)
        else:
            output = Path(args.output).expanduser()
            if not output.parent.exists():
                raise DumpError(f"output directory '{output.parent}' does not exist")
            output.write_text(report + "\n", encoding="utf-8")
            print(f"Report written to {output}")
        return 0
    except (DumpError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
