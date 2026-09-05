#!/usr/bin/env python3
"""Run a deterministic example workflow and propagate child failures."""

from __future__ import annotations

from pathlib import Path
import shlex
import subprocess
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
DEMOS = ROOT / "demo_files"


def run_tool(tool_name: str, *args: str) -> int:
    script = SCRIPTS / tool_name
    command = [sys.executable, str(script), *map(str, args)]
    print(f"\n{'=' * 60}")
    print(f"Running: {shlex.join(command)}")
    print("=" * 60)
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        print(f"Could not run {tool_name}: {exc}", file=sys.stderr)
        return 1
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
    if result.returncode != 0:
        print(f"[FAILED] {tool_name} exited with status {result.returncode}", file=sys.stderr)
    return result.returncode


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    print("CTF Toolkit - Workflow Example")
    print("=" * 60)
    failures: list[str] = []

    print("\n[STEP 1] Checking dependencies used by first-pass triage...")
    if run_tool("tool_check.py", "--profile", "triage") != 0:
        failures.append("dependency check")

    archive = DEMOS / "archive.zip"
    print("\n[STEP 2] Archive processing...")
    if archive.is_file():
        print(f"Archive fixture present: {archive}")
        print("Cracking is intentionally not started by this non-interactive example.")
    else:
        print("No archive fixture; skipping archive processing.")

    batch = DEMOS / "batch_test"
    print("\n[STEP 3] Finding a batch outlier...")
    if batch.is_dir() and run_tool("batch_diff.py", str(batch)) != 0:
        failures.append("batch analysis")

    encoded = DEMOS / "base64_demo.txt"
    print("\n[STEP 4] Triaging one unknown text file...")
    if encoded.is_file() and run_tool("triage.py", str(encoded)) != 0:
        failures.append("triage")

    print("\n[STEP 5] Running known-answer specialized examples...")
    examples = [
        ("encoding_decoder.py", ("--file", str(encoded), "--recursive")),
        (
            "cipher_solver.py",
            (str(DEMOS / "caesar_demo.txt"), "--cipher-type", "caesar", "--caesar-shift", "13"),
        ),
        (
            "xor_toolkit.py",
            (str(DEMOS / "xor_demo.bin"), "--mode", "repeating", "--key", "KEY"),
        ),
    ]
    for tool, arguments in examples:
        input_path = Path(arguments[1] if arguments[0] == "--file" else arguments[0])
        if not input_path.exists():
            print(f"Skipping {tool}: fixture {input_path} is missing")
            continue
        if run_tool(tool, *arguments) != 0:
            failures.append(tool)

    print("\n" + "=" * 60)
    if failures:
        print("Workflow completed with failures: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("Workflow example completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
