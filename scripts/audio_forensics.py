#!/usr/bin/env python3
"""Explicit, non-mutating-by-default audio forensics helpers."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Sequence


FLAG_PATTERNS = [r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"picoCTF\{[^}]+\}"]


class AudioError(ValueError):
    """A user-facing audio analysis error."""


def run_command(cmd: Sequence[str], timeout: int = 60) -> tuple[str, str, int]:
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


def check_tool(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def generate_spectrogram(filepath: str, output_path: str) -> tuple[str | None, str | None]:
    """Generate a WAV spectrogram at an explicit path."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from scipy.io import wavfile
    except ImportError as exc:
        return None, f"missing Python dependency: {exc} (run tool_check.py --profile audio)"

    try:
        sample_rate, data = wavfile.read(filepath)
        if getattr(data, "ndim", 1) > 1:
            data = data.mean(axis=1)
        destination = Path(output_path).expanduser()
        if not destination.parent.exists():
            return None, f"spectrogram directory '{destination.parent}' does not exist"
        figure = plt.figure(figsize=(12, 6))
        try:
            plt.specgram(data, Fs=sample_rate, cmap="viridis")
            plt.colorbar(format="%+2.0f dB")
            plt.xlabel("Time")
            plt.ylabel("Frequency")
            plt.title(f"Spectrogram: {Path(filepath).name}")
            plt.savefig(destination, dpi=150, bbox_inches="tight")
        finally:
            plt.close(figure)
        return str(destination), None
    except Exception as exc:  # scipy/matplotlib expose several format-specific exceptions.
        return None, str(exc)


def extract_id3_tags(filepath: str) -> tuple[dict[str, str] | None, str | None]:
    try:
        from mutagen.mp3 import MP3
    except ImportError:
        return None, "mutagen is not installed (sudo apt install python3-mutagen)"
    try:
        audio = MP3(filepath)
        if not audio.tags:
            return {}, None
        tags = {key: str(value) for key, value in audio.tags.items()}
        return tags, None
    except Exception as exc:
        return None, str(exc)


def extract_id3_via_exiftool(filepath: str) -> tuple[str | None, str | None]:
    if not check_tool("exiftool"):
        return None, "exiftool is not installed (sudo apt install libimage-exiftool-perl)"
    stdout, stderr, code = run_command(["exiftool", "--", str(Path(filepath).resolve())])
    return (stdout.strip(), None) if code == 0 else (None, stderr.strip() or "exiftool failed")


def extract_wavsteg(filepath: str, output_path: str | None = None) -> tuple[str | None, str | None]:
    if not check_tool("wavsteg"):
        return None, "wavsteg is not installed (see tool_check.py --profile audio)"
    command = ["wavsteg", str(Path(filepath).resolve())]
    if output_path:
        destination = Path(output_path).expanduser()
        if not destination.parent.exists():
            return None, f"wavsteg output directory '{destination.parent}' does not exist"
        command.extend(["-o", str(destination)])
    stdout, stderr, code = run_command(command)
    if code != 0:
        return None, stderr.strip() or stdout.strip() or f"wavsteg exited with status {code}"
    if output_path and Path(output_path).is_file():
        data = Path(output_path).read_bytes()
        try:
            rendered = data.decode("utf-8")
        except UnicodeDecodeError:
            rendered = f"hex:{data.hex()}"
        return rendered, None
    return stdout.strip(), None


def _find_flags(text: str) -> list[str]:
    flags: list[str] = []
    seen: set[str] = set()
    for pattern in FLAG_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            if match not in seen:
                seen.add(match)
                flags.append(match)
    return flags


def analyze_audio(
    filepath: str,
    spectrogram: str | None = None,
    run_wavsteg: bool = False,
    id3_only: bool = False,
    wavsteg_output: str | None = None,
) -> dict[str, object]:
    path = Path(filepath).expanduser().resolve()
    results: dict[str, object] = {
        "filepath": str(path),
        "file_type": None,
        "spectrogram": None,
        "id3_tags": None,
        "id3_fallback": None,
        "wavsteg_result": None,
        "flags": [],
        "warnings": [],
        "requested_errors": [],
    }

    if check_tool("file"):
        stdout, stderr, code = run_command(["file", "--", str(path)], timeout=30)
        if code == 0:
            results["file_type"] = stdout.strip()
        elif stderr.strip():
            results["warnings"].append(stderr.strip())
    else:
        results["warnings"].append("file is not installed (sudo apt install file)")

    lowered = str(results["file_type"] or "").lower()
    is_wav = "wave audio" in lowered or "wav" in lowered or path.suffix.lower() == ".wav"
    is_mp3 = "mp3" in lowered or "mpeg adts" in lowered or path.suffix.lower() == ".mp3"

    if id3_only:
        tags, error = extract_id3_tags(str(path))
        if tags is not None:
            results["id3_tags"] = tags
        else:
            fallback, fallback_error = extract_id3_via_exiftool(str(path))
            if fallback is not None:
                results["id3_fallback"] = fallback
            else:
                results["requested_errors"].append(error or fallback_error or "ID3 extraction failed")
        return results

    if spectrogram:
        if not is_wav:
            results["requested_errors"].append("spectrogram generation currently supports WAV input only")
        else:
            generated, error = generate_spectrogram(str(path), spectrogram)
            if generated:
                results["spectrogram"] = generated
            else:
                results["requested_errors"].append(error or "spectrogram generation failed")

    if run_wavsteg:
        if not is_wav:
            results["requested_errors"].append("wavsteg requires a WAV input")
        else:
            value, error = extract_wavsteg(str(path), wavsteg_output)
            if value is not None:
                results["wavsteg_result"] = value
            else:
                results["requested_errors"].append(error or "wavsteg failed")

    if is_mp3:
        tags, error = extract_id3_tags(str(path))
        if tags is not None:
            results["id3_tags"] = tags
        elif error:
            results["warnings"].append(error)

    if check_tool("strings"):
        stdout, stderr, code = run_command(["strings", "--", str(path)])
        if code == 0:
            results["flags"] = _find_flags(stdout)
        elif stderr.strip():
            results["warnings"].append(stderr.strip())
    else:
        results["warnings"].append("strings is not installed (sudo apt install binutils)")
    return results


def render_report(results: dict[str, object]) -> str:
    lines = [
        "Audio Forensics",
        "=" * 60,
        f"File: {results['filepath']}",
        f"Type: {results['file_type'] or 'Unknown (extension fallback used)'}",
    ]
    if results["spectrogram"]:
        lines.append(f"Spectrogram: {results['spectrogram']}")
    if results["id3_tags"] is not None:
        lines.append("ID3 tags:")
        tags = results["id3_tags"]
        if tags:
            lines.extend(f"  {key}: {value}" for key, value in tags.items())
        else:
            lines.append("  None")
    if results["id3_fallback"]:
        lines.extend(["ID3/exiftool fallback:", str(results["id3_fallback"])])
    if results["wavsteg_result"] is not None:
        lines.extend(["wavsteg:", str(results["wavsteg_result"])])
    lines.append("Flags:")
    flags = results["flags"]
    lines.extend(f"  {flag}" for flag in flags) if flags else lines.append("  None found")
    if results["warnings"]:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in results["warnings"])
    if results["requested_errors"]:
        lines.append("Requested operation errors:")
        lines.extend(f"  - {error}" for error in results["requested_errors"])
    return "\n".join(lines)


def write_report(report: str, output: str) -> None:
    if output == "console":
        print(report)
        return
    path = Path(output).expanduser()
    if not path.parent.exists():
        raise AudioError(f"output directory '{path.parent}' does not exist")
    path.write_text(report + "\n", encoding="utf-8")
    print(f"Report written to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audio metadata, strings, spectrogram, and LSB analysis")
    parser.add_argument("file", help="WAV or MP3 file")
    parser.add_argument("-s", "--spectrogram", help="Explicit spectrogram image path (WAV)")
    parser.add_argument("-w", "--wavsteg", action="store_true", help="Run wavsteg explicitly")
    parser.add_argument("--wavsteg-output", help="Optional wavsteg payload destination")
    parser.add_argument("--id3", action="store_true", help="Only extract ID3 metadata")
    parser.add_argument("--all", action="store_true", help="Run type-appropriate optional operations")
    parser.add_argument("--output", default="console", help="Text report output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        path = Path(args.file).expanduser()
        if not path.is_file():
            raise AudioError(f"audio file '{path}' was not found")
        if args.id3 and (args.spectrogram or args.wavsteg or args.all):
            raise AudioError("--id3 cannot be combined with spectrogram/wavsteg/all modes")
        if args.wavsteg_output and not (args.wavsteg or args.all):
            raise AudioError("--wavsteg-output requires --wavsteg or --all")

        spectrogram = args.spectrogram
        run_wavsteg = args.wavsteg
        if args.all and path.suffix.lower() == ".wav":
            spectrogram = spectrogram or str(path.with_name(f"{path.stem}_spectrogram.png"))
            run_wavsteg = True

        results = analyze_audio(
            str(path),
            spectrogram=spectrogram,
            run_wavsteg=run_wavsteg,
            id3_only=args.id3,
            wavsteg_output=args.wavsteg_output,
        )
        write_report(render_report(results), args.output)
        return 2 if results["requested_errors"] else 0
    except (AudioError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
