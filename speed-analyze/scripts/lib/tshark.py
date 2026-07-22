from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path


def _platform_candidates() -> list[Path]:
    system = platform.system()
    if system == "Windows":
        candidates = []
        for environment_variable in ("ProgramFiles", "ProgramFiles(x86)"):
            base_path = os.environ.get(environment_variable)
            if base_path:
                candidates.append(Path(base_path) / "Wireshark" / "tshark.exe")
        candidates.append(Path(r"C:\Program Files\Wireshark\tshark.exe"))
    elif system == "Darwin":
        candidates = [
            Path("/Applications/Wireshark.app/Contents/MacOS/tshark"),
            Path("/opt/homebrew/bin/tshark"),
            Path("/usr/local/bin/tshark"),
        ]
    else:
        candidates = []
    return candidates


def find_tshark(configured: str | None = None) -> Path:
    """Find a TShark executable using configured and platform-specific locations."""
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured))
    environment_path = os.environ.get("TSHARK_PATH")
    if environment_path:
        candidates.append(Path(environment_path))
    path_tshark = shutil.which("tshark")
    if path_tshark:
        candidates.append(Path(path_tshark))
    candidates.extend(_platform_candidates())

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("DEPENDENCY_UNAVAILABLE: TShark executable was not found")


def _invalid_capture(message: str, stderr: str = "") -> RuntimeError:
    suffix = f": {stderr[:500]}" if stderr else ""
    return RuntimeError(f"INVALID_CAPTURE: {message}{suffix}")


def normalize_capture(input_path: Path, output_dir: Path, tshark_path: Path) -> Path:
    """Return pcapng input directly or convert pcap input to pcapng."""
    input_path = Path(input_path)
    suffix = input_path.suffix.lower()
    if suffix == ".pcapng":
        return input_path.resolve()
    if suffix != ".pcap":
        raise _invalid_capture(f"unsupported capture extension: {input_path.suffix}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{input_path.stem}.pcapng"
    command = [str(tshark_path), "-r", str(input_path), "-w", str(output_path)]
    with tempfile.TemporaryFile(
        mode="w+", encoding="utf-8", errors="replace"
    ) as stderr_file:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise _invalid_capture(
                "TShark conversion could not start", str(exc)
            ) from exc
        if result.returncode != 0:
            stderr_file.seek(0)
            raise _invalid_capture(
                "TShark conversion failed", stderr_file.read(500)
            )
    if not output_path.is_file():
        raise _invalid_capture("TShark conversion did not create output")
    return output_path


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def stream_tshark_fields(
    tshark_path: Path,
    capture: Path,
    fields: list[str],
    display_filter: str,
) -> Iterator[dict[str, str]]:
    """Yield selected TShark fields one packet at a time."""
    command = [str(tshark_path), "-r", str(capture), "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])
    command.extend(["-Y", display_filter])

    with tempfile.TemporaryFile(
        mode="w+", encoding="utf-8", errors="replace"
    ) as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise RuntimeError(
                f"ANALYSIS_FAILED: TShark could not start: {exc}"
            ) from exc

        completed = False
        try:
            assert process.stdout is not None
            for line in process.stdout:
                values = line.rstrip("\r\n").split("\t")
                values.extend([""] * max(0, len(fields) - len(values)))
                yield dict(zip(fields, values))

            returncode = process.wait()
            completed = True
            if returncode != 0:
                stderr_file.seek(0)
                stderr = stderr_file.read(500)
                raise RuntimeError(
                    f"ANALYSIS_FAILED: TShark exited with {returncode}: {stderr}"
                )
        finally:
            if not completed:
                _terminate_process(process)
            if process.stdout is not None:
                process.stdout.close()
