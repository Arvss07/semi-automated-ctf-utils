#!/usr/bin/env python3
"""Profile-aware dependency checker for the CTF utility toolkit."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import shutil
import sys
from typing import Sequence


REQUIREMENTS: dict[str, dict[str, object]] = {
    "python3": {"kind": "executable", "install": "sudo apt install python3", "profiles": {"core"}},
    "file": {"kind": "executable", "install": "sudo apt install file", "profiles": {"triage", "archive", "stego", "audio"}},
    "exiftool": {"kind": "executable", "install": "sudo apt install libimage-exiftool-perl", "profiles": {"triage", "audio"}},
    "binwalk": {"kind": "executable", "install": "sudo apt install binwalk", "profiles": {"triage"}},
    "strings": {"kind": "executable", "install": "sudo apt install binutils", "profiles": {"triage", "audio"}},
    "steghide": {"kind": "executable", "install": "sudo apt install steghide", "profiles": {"stego"}},
    "stegseek": {"kind": "executable", "install": "Install from https://github.com/RickdeJager/stegseek/releases", "profiles": {"stego"}},
    "zsteg": {"kind": "executable", "install": "gem install zsteg", "profiles": {"stego"}},
    "hashcat": {"kind": "executable", "install": "sudo apt install hashcat", "profiles": {"hash"}},
    "john": {"kind": "executable", "install": "sudo apt install john", "profiles": {"hash", "archive"}},
    "rockyou": {"kind": "file", "path": "/usr/share/wordlists/rockyou.txt", "install": "sudo apt install wordlists", "profiles": {"hash", "archive", "stego"}},
    "zip2john": {"kind": "john-helper", "install": "sudo apt install john", "profiles": {"archive"}},
    "rar2john": {"kind": "john-helper", "install": "sudo apt install john", "profiles": {"archive"}},
    "7z2john": {"kind": "john-helper", "install": "sudo apt install john", "profiles": {"archive"}},
    "unzip": {"kind": "executable", "install": "sudo apt install unzip", "profiles": {"archive"}},
    "unrar": {"kind": "executable", "install": "sudo apt install unrar", "profiles": {"archive"}},
    "7z": {"kind": "executable", "install": "sudo apt install p7zip-full", "profiles": {"archive"}},
    "tshark": {"kind": "executable", "install": "sudo apt install tshark", "profiles": {"pcap"}},
    "wavsteg": {"kind": "executable", "install": "Install from https://github.com/ImTheCurse/wavSteg/releases", "profiles": {"audio"}},
    "numpy": {"kind": "python", "module": "numpy", "install": "sudo apt install python3-numpy", "profiles": {"audio"}},
    "scipy": {"kind": "python", "module": "scipy", "install": "sudo apt install python3-scipy", "profiles": {"audio"}},
    "matplotlib": {"kind": "python", "module": "matplotlib", "install": "sudo apt install python3-matplotlib", "profiles": {"audio"}},
    "mutagen": {"kind": "python", "module": "mutagen", "install": "sudo apt install python3-mutagen", "profiles": {"audio"}},
    "fls": {"kind": "executable", "install": "sudo apt install sleuthkit", "profiles": {"disk"}},
    "fsstat": {"kind": "executable", "install": "sudo apt install sleuthkit", "profiles": {"disk"}},
    "icat": {"kind": "executable", "install": "sudo apt install sleuthkit", "profiles": {"disk"}},
    "sqlite3-python": {"kind": "python", "module": "sqlite3", "install": "reinstall the Python standard library sqlite3 module", "profiles": {"database"}},
}

PROFILES = ("all", "core", "triage", "stego", "hash", "archive", "pcap", "audio", "disk", "database")


def check_tool(name: str, install_cmd: str) -> tuple[bool, str | None]:
    """Compatibility helper for executable checks."""
    return (True, None) if shutil.which(name) else (False, install_cmd)


def _john_helper_exists(name: str) -> bool:
    if shutil.which(name):
        return True
    return any((directory / name).is_file() for directory in (Path("/usr/share/john"), Path("/usr/lib/john")))


def requirement_found(name: str, config: dict[str, object]) -> tuple[bool, str | None]:
    kind = config["kind"]
    if kind == "executable":
        path = shutil.which(name)
        return path is not None, path
    if kind == "john-helper":
        return _john_helper_exists(name), shutil.which(name) or str(Path("/usr/share/john") / name)
    if kind == "file":
        path = Path(str(config["path"])).expanduser()
        return path.is_file(), str(path)
    module = str(config.get("module", name))
    return importlib.util.find_spec(module) is not None, f"Python module {module}"


def selected_requirements(profile: str) -> list[tuple[str, dict[str, object]]]:
    if profile == "all":
        return list(REQUIREMENTS.items())
    selected = []
    for name, config in REQUIREMENTS.items():
        profiles = set(config["profiles"])
        if profile in profiles or "core" in profiles:
            selected.append((name, config))
    return selected


def build_report(profile: str) -> tuple[str, int]:
    lines = [
        "CTF Toolkit - Dependency Check",
        "=" * 60,
        f"Profile: {profile}",
        "",
    ]
    missing: list[tuple[str, dict[str, object]]] = []
    found_count = 0
    requirements = selected_requirements(profile)
    for name, config in requirements:
        found, detail = requirement_found(name, config)
        if found:
            found_count += 1
            lines.append(f"[OK]      {name:<15} {detail or ''}".rstrip())
        else:
            missing.append((name, config))
            lines.append(f"[MISSING] {name:<15} Install: {config['install']}")

    lines.extend(
        [
            "",
            "=" * 60,
            f"Summary: {found_count} found, {len(missing)} missing",
        ]
    )
    if missing:
        lines.append("Missing requirements affect only the selected profile.")
    else:
        lines.append("All requirements for this profile are available.")
    return "\n".join(lines), 1 if missing else 0


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise ValueError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + "\n", encoding="utf-8")
    print(f"Dependency report written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check dependencies for one CTF toolkit profile")
    parser.add_argument("--profile", choices=PROFILES, default="all", help="Tool group to check")
    parser.add_argument("--output", default="console", help="Report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report, status = build_report(args.profile)
        write_report(report, args.output)
        return status
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
