#!/usr/bin/env python3
"""One-command hash cracking wrapper for hashcat and John the Ripper.

The positional INPUT may be an existing hash file or a raw hash value. Use
--file or --hash when an explicit source is preferable.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Sequence


DEFAULT_WORDLIST = Path("/usr/share/wordlists/rockyou.txt")
DEFAULT_MASK = "?a?a?a?a?a?a?a?a"
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")

HASHCAT_MODES = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "ntlm": 1000,
    "mysql": 300,
    "bcrypt": 3200,
    "md5crypt": 500,
    "sha256crypt": 7400,
    "sha512crypt": 1800,
    "zip": 13600,
    "rar5": 13000,
    "7z": 11600,
    "sha3-256": 17400,
    "sha3-512": 17600,
    "blake2b-512": 600,
    "blake2s-256": 31000,
    "argon2": 34000,
    "netntlmv1": 5500,
    "netntlmv2": 5600,
    "krb5tgs23": 13100,
    "krb5asrep23": 18200,
}

JOHN_FORMATS = {
    "md5": "Raw-MD5",
    "sha1": "Raw-SHA1",
    "sha256": "Raw-SHA256",
    "sha512": "Raw-SHA512",
    "ntlm": "NT",
    "mysql": "mysql-sha1",
    "bcrypt": "bcrypt",
    "md5crypt": "md5crypt",
    "sha256crypt": "sha256crypt",
    "sha512crypt": "sha512crypt",
    "pkzip": "PKZIP",
    "zip": "ZIP",
    "rar": "RAR",
    "rar5": "RAR5",
    "7z": "7z",
}

HASH_TYPES = tuple(
    dict.fromkeys(
        [
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "ntlm",
            "mysql",
            "bcrypt",
            "md5crypt",
            "sha256crypt",
            "sha512crypt",
            "pkzip",
            "zip",
            "rar",
            "rar5",
            "7z",
            "sha3-256",
            "sha3-512",
            "blake2b-512",
            "blake2s-256",
            "argon2",
            "netntlmv1",
            "netntlmv2",
            "krb5tgs23",
            "krb5asrep23",
        ]
    )
)


class CliError(ValueError):
    """A user-facing command-line validation error."""


def check_tool(tool_name: str) -> bool:
    """Return whether an executable is available on PATH."""
    return shutil.which(tool_name) is not None


def detect_hash_type(hash_string: str) -> str:
    """Strictly identify common hash formats from one hash line."""
    value = hash_string.strip()
    lowered = value.lower()

    if "$pkzip2$" in lowered:
        return "pkzip"
    if "$zip2$" in lowered:
        return "zip"
    if "$rar5$" in lowered:
        return "rar5"
    if "$rar3$" in lowered:
        return "rar"
    if "$7z$" in lowered:
        return "7z"
    if lowered.startswith(("$argon2d$", "$argon2i$", "$argon2id$")):
        return "argon2"
    if lowered.startswith("$krb5tgs$23$"):
        return "krb5tgs23"
    if lowered.startswith("$krb5asrep$23$"):
        return "krb5asrep23"
    if re.fullmatch(r"[^:\s]+::[^:\s]*:[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}:[0-9A-Fa-f]+", value):
        return "netntlmv2"
    if re.fullmatch(r"[^:\s]+::[^:\s]*:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{16}", value):
        return "netntlmv1"
    if re.search(r"\$2[aby]\$\d{2}\$", value):
        return "bcrypt"
    if value.startswith("$1$"):
        return "md5crypt"
    if value.startswith("$5$"):
        return "sha256crypt"
    if value.startswith("$6$"):
        return "sha512crypt"
    if re.fullmatch(r"\*[0-9A-Fa-f]{40}", value):
        return "mysql"
    if re.fullmatch(r"[^:\s]+:[0-9A-Fa-f]{32}", value):
        return "ntlm"
    if not re.fullmatch(r"[0-9A-Fa-f]+", value):
        return "unknown"

    return {
        32: "md5",
        40: "sha1",
        64: "sha256",
        128: "sha512",
    }.get(len(value), "unknown")


def get_hashcat_modes() -> dict[str, int]:
    """Return supported hashcat mode numbers."""
    return HASHCAT_MODES.copy()


def get_john_formats() -> dict[str, str]:
    """Return supported John format names."""
    return JOHN_FORMATS.copy()


def build_hashcat_command(
    hash_file: str,
    hash_type: str,
    wordlist: str | None = None,
    rule: str | None = None,
    increment: bool = False,
    mask: str | None = None,
    attack: str = "dictionary",
    session: str = "ctf",
) -> list[str]:
    """Build a hashcat argv list without invoking a shell."""
    if hash_type not in HASHCAT_MODES:
        raise CliError(
            f"hashcat mode is not known for '{hash_type}'; use --john or specify a supported type"
        )

    cmd = [
        "hashcat",
        "-m",
        str(HASHCAT_MODES[hash_type]),
        f"--session={session}",
    ]

    if attack == "dictionary":
        if not wordlist:
            raise CliError("dictionary attack requires a wordlist")
        cmd.extend(["-a", "0"])
        if rule:
            cmd.extend(["-r", rule])
        cmd.extend([hash_file, wordlist])
    elif attack == "mask":
        if not mask:
            raise CliError("mask attack requires --mask")
        cmd.extend(["-a", "3"])
        if increment:
            cmd.append("--increment")
        cmd.extend([hash_file, mask])
    elif attack == "bruteforce":
        cmd.extend(["-a", "3", "--increment", hash_file, mask or DEFAULT_MASK])
    else:
        raise CliError(f"unsupported attack: {attack}")

    return cmd


def build_john_command(
    hash_file: str,
    hash_type: str,
    wordlist: str | None = None,
    mask: str | None = None,
    attack: str = "dictionary",
    session: str = "ctf",
    rule: str | None = None,
) -> list[str]:
    """Build a John argv list using its required --option=value syntax."""
    fmt = JOHN_FORMATS.get(hash_type)
    if not fmt:
        raise CliError(
            f"John format is not known for '{hash_type}'; specify --type explicitly"
        )

    cmd = ["john", f"--format={fmt}", f"--session={session}"]

    if attack == "dictionary":
        if not wordlist:
            raise CliError("dictionary attack requires a wordlist")
        cmd.append(f"--wordlist={wordlist}")
        if rule:
            cmd.append(f"--rules={rule}")
    elif attack == "mask":
        if not mask:
            raise CliError("mask attack requires --mask")
        cmd.append(f"--mask={mask}")
    elif attack == "bruteforce":
        cmd.append("--incremental")
    else:
        raise CliError(f"unsupported attack: {attack}")

    cmd.append(hash_file)
    return cmd


def build_show_command(tool: str, hash_file: str, hash_type: str) -> list[str]:
    """Build the tool-specific command that prints recovered credentials."""
    if tool == "john":
        fmt = JOHN_FORMATS.get(hash_type)
        if not fmt:
            raise CliError(f"John format is not known for '{hash_type}'")
        return ["john", "--show", f"--format={fmt}", hash_file]

    mode = HASHCAT_MODES.get(hash_type)
    if mode is None:
        raise CliError(f"hashcat mode is not known for '{hash_type}'")
    return ["hashcat", "--show", "-m", str(mode), hash_file]


def _read_hash_lines(hash_file: Path, limit: int = 100) -> list[str]:
    try:
        with hash_file.open("r", encoding="utf-8", errors="replace") as handle:
            lines = [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        raise CliError(f"cannot read hash file '{hash_file}': {exc}") from exc

    if not lines:
        raise CliError(f"hash file '{hash_file}' is empty")
    return lines[:limit]


def detect_file_hash_type(hash_file: Path) -> str:
    """Detect a consistent type from the first non-empty hash lines."""
    detected = {detect_hash_type(line) for line in _read_hash_lines(hash_file)}
    detected.discard("unknown")
    if not detected:
        return "unknown"
    if len(detected) > 1:
        choices = ", ".join(sorted(detected))
        raise CliError(f"hash file appears to contain mixed types ({choices}); split it or use --type")
    return detected.pop()


def _write_raw_hash(value: str) -> Path:
    raw = value.strip()
    if not raw:
        raise CliError("raw hash value is empty")

    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="ctf-hash-",
        suffix=".txt",
        delete=False,
    )
    try:
        handle.write(raw)
        if not raw.endswith("\n"):
            handle.write("\n")
    finally:
        handle.close()
    return Path(handle.name)


def resolve_hash_source(args: argparse.Namespace) -> tuple[Path, bool]:
    """Resolve explicit or positional input to a hash file.

    Returns ``(path, is_temporary)``. The caller owns temporary cleanup.
    """
    supplied = [args.input is not None, args.hash_value is not None, args.hash_file is not None]
    if sum(supplied) != 1:
        raise CliError("provide exactly one INPUT, --hash VALUE, or --file PATH")

    if args.hash_file is not None:
        path = Path(args.hash_file).expanduser()
        if not path.is_file():
            raise CliError(f"hash file '{path}' was not found or is not a regular file")
        return path, False

    if args.hash_value is not None:
        return _write_raw_hash(args.hash_value), True

    positional = args.input
    assert positional is not None
    path = Path(positional).expanduser()
    if path.is_file():
        return path, False
    if path.exists():
        raise CliError(f"input path '{path}' is not a regular file")
    return _write_raw_hash(positional), True


def select_tool(requested: str | None, hash_type: str) -> str:
    """Select an installed cracker that supports the detected type."""
    if requested:
        if not check_tool(requested):
            raise CliError(f"{requested} is not installed (install with: sudo apt install {requested})")
        supported = JOHN_FORMATS if requested == "john" else HASHCAT_MODES
        if hash_type not in supported:
            raise CliError(f"{requested} does not have a configured format for '{hash_type}'")
        return requested

    if hash_type in HASHCAT_MODES and check_tool("hashcat"):
        return "hashcat"
    if hash_type in JOHN_FORMATS and check_tool("john"):
        return "john"

    if not check_tool("hashcat") and not check_tool("john"):
        raise CliError("neither hashcat nor John is installed (install with: sudo apt install hashcat john)")
    raise CliError(f"no installed cracker has a configured format for '{hash_type}'")


def resolve_attack(args: argparse.Namespace) -> tuple[str, str | None, str | None]:
    """Resolve attack mode and validate wordlist/rule paths."""
    attack = args.attack
    if attack is None:
        if args.mask:
            attack = "mask"
        elif args.increment:
            attack = "bruteforce"
        else:
            attack = "dictionary"

    wordlist: str | None = args.wordlist
    if attack == "dictionary":
        if not wordlist and DEFAULT_WORDLIST.is_file():
            wordlist = str(DEFAULT_WORDLIST)
        if not wordlist:
            raise CliError("dictionary attack requires --wordlist (default rockyou.txt was not found)")
        if not Path(wordlist).expanduser().is_file():
            raise CliError(f"wordlist '{wordlist}' was not found")
        wordlist = str(Path(wordlist).expanduser())
    elif args.wordlist:
        raise CliError("--wordlist is only valid for dictionary attacks")

    rule = args.rule
    if rule and attack != "dictionary":
        raise CliError("--rule is only valid for dictionary attacks")
    if rule and args.hashcat and not Path(rule).expanduser().is_file():
        raise CliError(f"hashcat rule file '{rule}' was not found")

    if attack == "mask" and not args.mask:
        raise CliError("mask attack requires --mask")

    return attack, wordlist, rule


def _run(cmd: Sequence[str], capture: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(cmd),
            capture_output=capture,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CliError(f"command not found: {cmd[0]}") from exc
    except OSError as exc:
        raise CliError(f"could not run {cmd[0]}: {exc}") from exc


def extract_cracked_lines(output: str) -> list[str]:
    """Remove John/hashcat status lines from ``--show`` output."""
    cracked: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^\d+\s+password hash(?:es)? cracked,", line, re.IGNORECASE):
            continue
        if line.lower().startswith(("no password hashes", "session completed")):
            continue
        cracked.append(line)
    return cracked


def write_results(lines: list[str], output: str) -> None:
    """Print cracked lines or write them to a requested text file."""
    payload = "\n".join(lines)
    if output == "console":
        print("\nCracked passwords:")
        print(payload)
        return

    path = Path(output).expanduser()
    if not path.parent.exists():
        raise CliError(f"output directory '{path.parent}' does not exist")
    try:
        path.write_text(payload + ("\n" if payload else ""), encoding="utf-8")
    except OSError as exc:
        raise CliError(f"could not write output '{path}': {exc}") from exc
    print(f"\nCracked passwords written to {path}")


def execute(args: argparse.Namespace) -> int:
    """Validate arguments, run the selected cracker, and report results."""
    if not SESSION_PATTERN.fullmatch(args.session):
        raise CliError("session may contain only letters, digits, '.', '_' and '-'")

    hash_file, temporary = resolve_hash_source(args)
    try:
        detected = detect_file_hash_type(hash_file)
        hash_type = args.hash_type or detected
        if hash_type == "unknown":
            raise CliError("input is not a valid hash in a recognized format; use --type for an uncommon format")

        if args.hash_type and detected not in {"unknown", args.hash_type}:
            print(
                f"Warning: input looks like {detected}, but --type {args.hash_type} was requested",
                file=sys.stderr,
            )

        requested = "john" if args.john else "hashcat" if args.hashcat else None
        tool = select_tool(requested, hash_type)

        if not args.show:
            attack, wordlist, rule = resolve_attack(args)

        if args.output != "console":
            output_path = Path(args.output).expanduser().resolve()
            try:
                source_path = hash_file.resolve()
            except OSError:
                source_path = hash_file.absolute()
            if not temporary and output_path == source_path:
                raise CliError("--output must not overwrite the input hash file")

        print(f"Hash type: {hash_type}")
        print(f"Tool: {tool}")

        if not args.show:
            if tool == "john":
                crack_cmd = build_john_command(
                    str(hash_file),
                    hash_type,
                    wordlist=wordlist,
                    mask=args.mask,
                    attack=attack,
                    session=args.session,
                    rule=rule,
                )
            else:
                crack_cmd = build_hashcat_command(
                    str(hash_file),
                    hash_type,
                    wordlist=wordlist,
                    rule=rule,
                    increment=args.increment,
                    mask=args.mask,
                    attack=attack,
                    session=args.session,
                )

            print(f"Running: {shlex.join(crack_cmd)}")
            crack_result = _run(crack_cmd)
            accepted_codes = {0} if tool == "john" else {0, 1}
            if crack_result.returncode not in accepted_codes:
                can_fallback = (
                    requested is None
                    and tool == "hashcat"
                    and hash_type in JOHN_FORMATS
                    and check_tool("john")
                )
                if not can_fallback:
                    print(
                        f"Error: {tool} exited with status {crack_result.returncode}",
                        file=sys.stderr,
                    )
                    return crack_result.returncode or 1

                print(
                    f"Warning: hashcat exited with status {crack_result.returncode}; "
                    "falling back to John",
                    file=sys.stderr,
                )
                tool = "john"
                print(f"Tool: {tool}")
                crack_cmd = build_john_command(
                    str(hash_file),
                    hash_type,
                    wordlist=wordlist,
                    mask=args.mask,
                    attack=attack,
                    session=args.session,
                    rule=rule,
                )
                print(f"Running: {shlex.join(crack_cmd)}")
                crack_result = _run(crack_cmd)
                if crack_result.returncode != 0:
                    print(
                        f"Error: John exited with status {crack_result.returncode}",
                        file=sys.stderr,
                    )
                    return crack_result.returncode or 1

        show_cmd = build_show_command(tool, str(hash_file), hash_type)
        show_result = _run(show_cmd, capture=True)
        if show_result.returncode != 0:
            detail = show_result.stderr.strip() or show_result.stdout.strip()
            if detail:
                print(detail, file=sys.stderr)
            return show_result.returncode or 1

        cracked = extract_cracked_lines(show_result.stdout)
        if not cracked:
            print("No password was recovered.", file=sys.stderr)
            return 2

        write_results(cracked, args.output)
        return 0
    finally:
        if temporary:
            try:
                hash_file.unlink()
            except FileNotFoundError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crack a raw hash or hash file with hashcat/John",
        allow_abbrev=False,
    )
    parser.add_argument("input", nargs="?", help="Raw hash value or existing hash file")
    parser.add_argument("--hash", dest="hash_value", help="Explicit raw hash value")
    parser.add_argument("--file", dest="hash_file", help="Explicit hash file path")
    parser.add_argument("-t", "--type", dest="hash_type", choices=HASH_TYPES, help="Hash type")
    parser.add_argument("-w", "--wordlist", help="Dictionary wordlist (defaults to rockyou.txt)")
    parser.add_argument(
        "--attack",
        choices=["dictionary", "mask", "bruteforce"],
        help="Attack mode (default: dictionary)",
    )
    parser.add_argument("--mask", help="Mask for a mask attack")
    parser.add_argument("--increment", action="store_true", help="Increment mask length or use brute force")
    parser.add_argument("--rule", help="Hashcat rule file or John rule section")
    parser.add_argument("--session", default="ctf", help="Restorable cracker session name")
    parser.add_argument("--output", default="console", help="Recovered hashes/passwords output path")
    parser.add_argument("--show", action="store_true", help="Only show credentials already in the potfile")
    parser.add_argument("-i", "--interactive", action="store_true", help="Prompt for cracking options")

    tool_group = parser.add_mutually_exclusive_group()
    tool_group.add_argument("--auto", action="store_true", help="Select the first installed compatible tool")
    tool_group.add_argument("--hashcat", action="store_true", help="Force hashcat")
    tool_group.add_argument("--john", action="store_true", help="Force John the Ripper")
    return parser


def interactive_menu() -> int:
    """Collect a small set of common options and delegate to the normal CLI."""
    print("=" * 60)
    print("Hash Cracking Wrapper")
    print("=" * 60)
    source = input("Raw hash or hash file: ").strip()
    if not source:
        print("Error: input is required", file=sys.stderr)
        return 2

    detected = detect_hash_type(source)
    hash_type = input(f"Hash type [{detected if detected != 'unknown' else 'auto'}]: ").strip()

    available = [name for name in ("hashcat", "john") if check_tool(name)]
    if not available:
        print("Error: install hashcat or John", file=sys.stderr)
        return 1
    print("Available tools: " + ", ".join(available))
    tool = input(f"Tool [{available[0]}]: ").strip().lower() or available[0]
    if tool not in available:
        print(f"Error: '{tool}' is not available", file=sys.stderr)
        return 2

    wordlist = input(f"Wordlist [{DEFAULT_WORDLIST}]: ").strip() or str(DEFAULT_WORDLIST)
    session = input("Session [ctf]: ").strip() or "ctf"
    confirm = input("Start cracking? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes"}:
        print("Cancelled")
        return 0

    argv = [source, f"--{tool}", "--wordlist", wordlist, "--session", session]
    if hash_type:
        argv.extend(["--type", hash_type])
    return main(argv)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = list(argv) if argv is not None else sys.argv[1:]

    if not arguments and sys.stdin.isatty():
        return interactive_menu()

    args = parser.parse_args(arguments)
    if args.interactive:
        return interactive_menu()

    try:
        return execute(args)
    except CliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted. Restore the named session with the selected cracker.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
