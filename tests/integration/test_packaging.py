from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path


def _venv_python(environment: Path) -> Path:
    if sys.platform == "win32":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _venv_script(environment: Path, name: str) -> Path:
    if sys.platform == "win32":
        return environment / "Scripts" / f"{name}.exe"
    return environment / "bin" / name


def test_wheel_install_contains_default_speed_analyze_runtime(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    wheelhouse = tmp_path / "wheels"
    built = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheelhouse),
            str(root),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    wheels = list(wheelhouse.glob("packetmaster-*.whl"))
    assert len(wheels) == 1

    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(environment)
    python = _venv_python(environment)
    installed = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr

    for command in ("packetmaster", "pkm"):
        executable = _venv_script(environment, command)
        help_result = subprocess.run(
            [str(executable), "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        assert executable.is_file()
        assert help_result.returncode == 0, help_result.stdout + help_result.stderr
        assert "PacketMaster" in help_result.stdout

    outside_repository = tmp_path / "outside"
    outside_repository.mkdir()
    smoke = subprocess.run(
        [
            str(python),
            "-c",
            "from pathlib import Path; "
            "from packetmaster.analyzer.real import RealAnalyzerAdapter; "
            "from packetmaster.model import DiagnosisModel; "
            "from packetmaster.web.runtime import static_directory; "
            "adapter = RealAnalyzerAdapter(artifact_root=Path('artifacts')); "
            "assert adapter.pipeline_script.is_file(), adapter.pipeline_script; "
            "assert DiagnosisModel._prompt('general_chat.md'); "
            "assert (static_directory() / 'index.html').is_file(); "
            "print(adapter.pipeline_script)",
        ],
        cwd=outside_repository,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert smoke.returncode == 0, smoke.stdout + smoke.stderr
