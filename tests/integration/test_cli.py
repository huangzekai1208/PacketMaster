from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from typer.testing import CliRunner

import packetmaster.cli as cli
from packetmaster.config import Settings
from packetmaster.domain import Confidence, CoverageSummary, DiagnosticReport, Target
from packetmaster.errors import AppError
from tests.fakes import FakeDiagnosisModel

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
CAPTURE_GENERATOR = ROOT / "scripts" / "generate_test_capture.py"


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
    ("message", "expected"),
    [
        ("Starting speed analysis", "正在启动测速分析"),
        ("Inputs validated", "输入参数校验完成"),
        ("Normalizing capture", "正在规范化报文文件"),
        ("Capture normalized", "报文文件规范化完成"),
        ("Fingerprinting capture", "正在计算报文指纹"),
        ("Scanning capture flows", "正在扫描报文流"),
        ("Scanned 200000 packets", "已扫描 200000 个报文"),
        ("Fingerprint completed", "报文指纹计算完成"),
        ("Capture scan completed", "报文扫描完成"),
        ("Writing filtered captures", "正在写入筛选后的报文"),
        ("Filtering completed", "报文筛选完成"),
        (
            "Extracting all download TCP packets",
            "正在提取全部下载方向 TCP 报文",
        ),
        (
            "Extracted 100000 upload TCP packets",
            "已提取 100000 个上行方向 TCP 报文",
        ),
        (
            "Completed download TCP extraction",
            "下载方向 TCP 报文提取完成",
        ),
        ("Analysis completed", "分析完成"),
        ("Analysis partial", "分析部分完成"),
        ("Speed analysis process completed", "测速分析进程完成"),
        ("未知阶段", "未知阶段"),
        ("Future pipeline stage", "分析处理中"),
    ],
)
def test_cli_localizes_progress_messages(message: str, expected: str) -> None:
    assert cli._localize_progress_message(message) == expected


def test_run_diagnosis_prints_localized_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeClient:
        def __init__(self, server, progress_callback) -> None:
            self.progress_callback = progress_callback

        async def __aenter__(self):
            self.progress_callback(0.0, "Starting speed analysis")
            self.progress_callback(0.5, "Extracted 100000 download TCP packets")
            return self

        async def __aexit__(self, exc_type, exc, traceback) -> None:
            pass

    class FakeGraph:
        async def ainvoke(self, state):
            return {"report": _report(Target.DOWNLOAD), "trace": []}

    monkeypatch.setattr(cli, "RealAnalyzerAdapter", lambda **kwargs: object())
    monkeypatch.setattr(cli, "create_server", lambda adapter: object())
    monkeypatch.setattr(cli, "SpeedMCPClient", FakeClient)
    monkeypatch.setattr(cli, "DiagnosisModel", lambda **kwargs: object())
    monkeypatch.setattr(cli, "ContextBuilder", lambda: object())
    monkeypatch.setattr(cli, "build_graph", lambda **kwargs: FakeGraph())

    asyncio.run(
        cli.run_diagnosis(
            pcap_path=str((tmp_path / "capture.pcapng").resolve()),
            standard=1000,
            actual=600,
            target=Target.DOWNLOAD,
            request_id="localized-progress",
            settings=Settings(artifact_root=tmp_path / "artifacts"),
        )
    )

    output = capsys.readouterr().out
    assert "[进度] 正在启动测速分析" in output
    assert "[进度] 已提取 100000 个下载方向 TCP 报文" in output
    assert "Starting speed analysis" not in output


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


def test_cli_resolves_relative_capture_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "captures" / "test.pcapng"
    capture.parent.mkdir()
    capture.write_bytes(b"capture")
    calls: list[str] = []

    async def fake_run(**kwargs):
        calls.append(kwargs["pcap_path"])
        return _report(Target.DOWNLOAD)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "run_diagnosis", fake_run)
    result = runner.invoke(
        cli.app,
        [
            "diagnose",
            "captures/test.pcapng",
            "--standard",
            "1000",
            "--actual",
            "600",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [str(capture.resolve())]


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


def test_cli_writes_degraded_report_when_base_analysis_succeeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    report = _report(Target.DOWNLOAD)
    report.analysis_metadata["error_code"] = "MODEL_CALL_FAILED"
    error = AppError(
        code="MODEL_CALL_FAILED",
        message="model unavailable",
        recoverable=True,
        suggested_action="retry model diagnosis",
    )

    async def fake_run(**kwargs):
        return cli.DiagnosisOutcome(report=report, error=error)

    monkeypatch.setattr(cli, "run_diagnosis", fake_run)
    output = tmp_path / "degraded"
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
        ],
    )

    assert result.exit_code == 2
    saved = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert saved["primary_cause"] == "unresolved"
    assert saved["analysis_metadata"]["error_code"] == "MODEL_CALL_FAILED"
    assert "MODEL_CALL_FAILED" in result.output


def test_run_diagnosis_raises_error_returned_by_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback) -> None:
            pass

    class FakeGraph:
        async def ainvoke(self, state):
            return {
                "report": _report(Target.DOWNLOAD),
                "error": {
                    "code": "ANALYSIS_FAILED",
                    "message": "failed",
                    "recoverable": True,
                    "suggested_action": "retry",
                    "details": {"stage": "analyze"},
                },
            }

    monkeypatch.setattr(cli, "RealAnalyzerAdapter", lambda **kwargs: object())
    monkeypatch.setattr(cli, "create_server", lambda adapter: object())
    monkeypatch.setattr(cli, "SpeedMCPClient", FakeClient)
    monkeypatch.setattr(cli, "DiagnosisModel", lambda **kwargs: object())
    monkeypatch.setattr(cli, "ContextBuilder", lambda: object())
    monkeypatch.setattr(cli, "build_graph", lambda **kwargs: FakeGraph())

    with pytest.raises(AppError) as raised:
        asyncio.run(
            cli.run_diagnosis(
                pcap_path=str((tmp_path / "capture.pcapng").resolve()),
                standard=1000,
                actual=600,
                target=Target.DOWNLOAD,
                request_id="graph-error",
                settings=Settings(artifact_root=tmp_path / "artifacts"),
            )
        )

    assert raised.value.to_dict() == {
        "code": "ANALYSIS_FAILED",
        "message": "failed",
        "recoverable": True,
        "suggested_action": "retry",
        "details": {"stage": "analyze"},
    }


def test_cli_wraps_settings_failure_as_structured_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")

    def fail_settings():
        raise RuntimeError("invalid settings")

    monkeypatch.setattr(cli.Settings, "load", fail_settings)
    result = runner.invoke(
        cli.app,
        [
            "diagnose",
            str(capture.resolve()),
            "--standard",
            "1000",
            "--actual",
            "600",
        ],
    )

    assert result.exit_code == 1
    error = json.loads(result.output)
    assert error["code"] == "CLI_FAILED"
    assert error["details"] == {"exception_type": "RuntimeError"}


def test_cli_wraps_output_path_resolution_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")

    class BrokenPath:
        def __init__(self, value: str) -> None:
            pass

        def expanduser(self):
            return self

        def resolve(self):
            raise OSError("output path unavailable")

    monkeypatch.setattr(cli, "Path", BrokenPath)
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
            "unavailable-output",
        ],
    )

    assert result.exit_code == 1
    error = json.loads(result.output)
    assert error["code"] == "CLI_FAILED"
    assert error["details"] == {"exception_type": "OSError"}


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


def test_cli_cleans_expired_artifacts_before_diagnosis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    artifact_root = tmp_path / "artifacts"
    manager = cli.ArtifactManager(artifact_root, ttl_hours=1)
    expired = manager.create("expired")
    old = time.time() - 7200
    os.utime(expired.root, (old, old))
    settings = Settings(artifact_root=artifact_root, artifact_ttl_hours=1)

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
            str(tmp_path / "report"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert not expired.root.exists()


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ([], "download"),
        (["--target", "upload"], "upload"),
        (["--target", "both"], "both"),
    ],
)
def test_cli_real_agent_smoke_preserves_target_and_writes_evidence_report(
    tmp_path: Path,
    tshark_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra: list[str],
    expected: str,
) -> None:
    api_key = f"sk-agent-smoke-{expected}"

    class RecordingDiagnosisModel(FakeDiagnosisModel):
        def __init__(self) -> None:
            super().__init__()
            self.model_inputs: list[object] = []

        async def generate_hypotheses(self, context):
            self.model_inputs.append(context.model_dump(mode="json"))
            return await super().generate_hypotheses(context)

        async def verify(self, context, hypotheses, evidence):
            self.model_inputs.append(
                {
                    "context": context.model_dump(mode="json"),
                    "hypotheses": hypotheses.model_dump(mode="json"),
                    "evidence": [item.model_dump(mode="json") for item in evidence],
                }
            )
            return await super().verify(context, hypotheses, evidence)

    capture = (tmp_path / f"agent-{expected}.pcapng").resolve()
    generated = subprocess.run(
        [
            sys.executable,
            str(CAPTURE_GENERATOR),
            "--output",
            str(capture),
            "--target",
            expected,
            "--flows",
            "2",
            "--data-packets-per-flow",
            "500",
            "--anomaly-after",
            "1000",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr
    settings = Settings(
        artifact_root=tmp_path / "artifacts",
        tshark_path=str(tshark_path),
        model_api_key=api_key,
    )
    model = RecordingDiagnosisModel()
    monkeypatch.setattr(cli.Settings, "load", lambda: settings)

    def build_model(**kwargs):
        configured = kwargs["settings"].model_api_key
        assert configured.get_secret_value() == api_key
        return model

    monkeypatch.setattr(cli, "DiagnosisModel", build_model)
    output = tmp_path / f"report-{expected}"

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
            str(output),
            *extra,
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["target"] == expected
    assert report["coverage_summary"]["speed_packets_analyzed"] > 0
    assert report["coverage_summary"]["complete"] is True
    assert report["primary_cause"] == "开放式候选原因"
    assert report["key_evidence"][0]["evidence_type"] == "retransmission"
    assert report["key_evidence"][0]["total"] > 0
    assert model.targets == [expected]
    serialized_inputs = json.dumps(model.model_inputs, ensure_ascii=False)
    assert api_key not in serialized_inputs
    assert "tcp.payload" not in serialized_inputs.lower()
    assert "A" * 64 not in serialized_inputs
    local_text = ""
    for path in settings.artifact_root.rglob("*"):
        if path.is_file() and path.suffix in {".json", ".jsonl", ".log"}:
            local_text += path.read_text(encoding="utf-8", errors="replace")
    assert api_key not in local_text
    trace_files = list(settings.artifact_root.glob("*/trace.jsonl"))
    assert len(trace_files) == 1
    trace = trace_files[0].read_text(encoding="utf-8")
    trace_events = [json.loads(line) for line in trace.splitlines()]
    assert trace_events[0]["node"] == "validate"
    assert trace_events[-1]["node"] == "report"
    assert api_key not in trace


@pytest.mark.skipif(
    sys.platform != "win32", reason="Windows CTRL_BREAK release gate"
)
def test_windows_real_cli_cancellation_terminates_pipeline_tree(
    tmp_path: Path, tshark_path: Path
) -> None:
    capture = (tmp_path / "cancel capture.pcapng").resolve()
    generated = subprocess.run(
        [
            sys.executable,
            str(CAPTURE_GENERATOR),
            "--output",
            str(capture),
            "--flows",
            "2",
            "--data-packets-per-flow",
            "25000",
            "--anomaly-after",
            "5000",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    assert generated.returncode == 0, generated.stdout + generated.stderr

    artifact_root = (tmp_path / "cancel artifacts").resolve()
    report_root = (tmp_path / "cancel report").resolve()
    environment = os.environ.copy()
    environment.update(
        ARTIFACT_ROOT=str(artifact_root),
        TSHARK_PATH=str(tshark_path),
    )
    console_log = tmp_path / "cancel-cli.log"
    descendants: list[psutil.Process] = []

    def command_line(child: psutil.Process) -> str:
        try:
            return " ".join(child.cmdline())
        except psutil.Error:
            return ""

    with console_log.open("w", encoding="utf-8", errors="replace") as output:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "packetmaster.cli",
                "diagnose",
                str(capture),
                "--standard",
                "1000",
                "--actual",
                "600",
                "--output-dir",
                str(report_root),
            ],
            cwd=ROOT,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and process.poll() is None:
            try:
                descendants = psutil.Process(process.pid).children(recursive=True)
            except psutil.Error:
                descendants = []
            if any(
                "run_pipeline.py" in command_line(child)
                for child in descendants
                if child.is_running()
            ):
                break
            time.sleep(0.05)
        else:
            process.kill()
            process.wait(timeout=10)
            pytest.fail("real speed-analyze child did not start before timeout")

        process.send_signal(signal.CTRL_BREAK_EVENT)
        returncode = process.wait(timeout=30)

    _, alive = psutil.wait_procs(descendants, timeout=10)
    assert returncode != 0
    assert alive == []
    task_roots = [path for path in artifact_root.iterdir() if path.is_dir()]
    assert len(task_roots) == 1
    assert (task_roots[0] / "logs" / "pipeline.log").is_file()
    assert not (report_root / "report.json").exists()
