from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import packetmaster.cli as cli
from packetmaster.config import Settings
from packetmaster.domain import Confidence, CoverageSummary, DiagnosticReport, Target
from packetmaster.errors import AppError

runner = CliRunner()


def _report(target: Target) -> DiagnosticReport:
    return DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
        achievement_ratio_pct=60,
        target=target,
        primary_cause="unresolved",
        key_evidence=[{"metric": "retransmission_rate", "value": 0.12}],
        confidence=Confidence.LOW,
        coverage_summary=CoverageSummary(
            total_packets_seen=10,
            tcp_packets_seen=10,
            speed_packets_analyzed=10,
            complete=True,
            truncated=False,
        ),
        limitations=["证据不足"],
    )


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ([], "download"),
        (["--target", "upload"], "upload"),
        (["--target", "both"], "both"),
    ],
)
def test_cli_default_and_explicit_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra: list[str],
    expected: str,
) -> None:
    capture = tmp_path / "中文 capture.pcapng"
    capture.write_bytes(b"capture")
    calls: list[tuple[str, str]] = []

    async def fake_run(**kwargs):
        calls.append((kwargs["pcap_path"], kwargs["target"].value))
        return _report(kwargs["target"])

    monkeypatch.setattr(cli, "run_diagnosis", fake_run)
    output = tmp_path / "reports"
    result = runner.invoke(
        cli.app,
        [
            "diagnose",
            str(capture.resolve()),
            "--standard",
            "1000",
            "--actual",
            "600",
            "--output-dir",
            str(output),
            *extra,
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [(str(capture.resolve()), expected)]
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["target"] == expected
    assert "分析方向" in result.output
    assert "关键证据: 1 条" in result.output
    assert "retransmission_rate" not in result.output
    assert expected in result.output


def test_cli_accepts_windows_drive_path_without_shell_rewriting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def fake_run(**kwargs):
        calls.append(kwargs["pcap_path"])
        return _report(Target.DOWNLOAD)

    monkeypatch.setattr(cli, "run_diagnosis", fake_run)
    windows_path = r"C:\测速 文件\capture.pcapng"
    result = runner.invoke(
        cli.app,
        [
            "diagnose",
            windows_path,
            "--standard",
            "1000",
            "--actual",
            "600",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert calls == [windows_path]


def test_cli_maps_app_error_to_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")

    async def fake_run(**kwargs):
        raise AppError(
            code="ANALYSIS_FAILED",
            message="failed",
            recoverable=True,
            suggested_action="retry",
        )

    monkeypatch.setattr(cli, "run_diagnosis", fake_run)
    result = runner.invoke(
        cli.app,
        [
            "diagnose",
            str(capture),
            "--standard",
            "1000",
            "--actual",
            "600",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2
    assert "ANALYSIS_FAILED" in result.output
    assert not (tmp_path / "out" / "report.json").exists()


def test_cli_keep_artifacts_writes_keep_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    artifact_root = tmp_path / "artifacts"
    settings = Settings(artifact_root=artifact_root)

    async def fake_run(**kwargs):
        return _report(kwargs["target"])

    monkeypatch.setattr(cli.Settings, "load", lambda: settings)
    monkeypatch.setattr(cli, "run_diagnosis", fake_run)
    result = runner.invoke(
        cli.app,
        [
            "diagnose",
            str(capture.resolve()),
            "--standard",
            "1000",
            "--actual",
            "600",
            "--output-dir",
            str(tmp_path / "out"),
            "--keep-artifacts",
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(list(artifact_root.glob("*/.keep"))) == 1
