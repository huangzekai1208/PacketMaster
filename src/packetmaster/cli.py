"""PacketMaster command-line entry point."""

from __future__ import annotations

import asyncio
import builtins
import json
import re
import time
from pathlib import Path
from typing import Annotated

import typer

from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.application import (
    DiagnosisOutcome,
    DiagnosisProgress,
    DiagnosisService,
)
from packetmaster.artifacts import ArtifactManager, create_request_id
from packetmaster.chat import (
    ChatCommand,
    ChatSession,
    ConversationRoute,
    parse_command,
    route_conversation,
)
from packetmaster.chat_graph import build_chat_graph
from packetmaster.config import Settings
from packetmaster.domain import (
    ChatSessionState,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.mcp.client import SpeedMCPClient
from packetmaster.mcp.server import create_server
from packetmaster.model import DiagnosisModel
from packetmaster.platform import is_absolute_path
from packetmaster.report import render_chat_report, render_terminal, write_report

app = typer.Typer(help="PacketMaster TCP 测速不达标诊断")

_PROGRESS_MESSAGES = {
    "Starting speed analysis": "正在启动测速分析",
    "Inputs validated": "输入参数校验完成",
    "Normalizing capture": "正在规范化报文文件",
    "Capture normalized": "报文文件规范化完成",
    "Fingerprinting capture": "正在计算报文指纹",
    "Scanning capture flows": "正在扫描报文流",
    "Fingerprint completed": "报文指纹计算完成",
    "Capture scan completed": "报文扫描完成",
    "Writing filtered captures": "正在写入筛选后的报文",
    "Filtering completed": "报文筛选完成",
    "Analysis completed": "分析完成",
    "Analysis partial": "分析部分完成",
    "Speed analysis process completed": "测速分析进程完成",
}
_DIRECTION_LABELS = {
    "download": "下载方向",
    "upload": "上行方向",
    "both": "上下行方向",
}


def _localize_progress_message(message: str) -> str:
    localized = _PROGRESS_MESSAGES.get(message)
    if localized is not None:
        return localized

    match = re.fullmatch(r"Scanned (\d+) packets", message)
    if match is not None:
        return f"已扫描 {match.group(1)} 个报文"

    match = re.fullmatch(r"Extracting all (download|upload|both) TCP packets", message)
    if match is not None:
        direction = _DIRECTION_LABELS[match.group(1)]
        return f"正在提取全部{direction} TCP 报文"

    match = re.fullmatch(
        r"Extracted (\d+) (download|upload|both) TCP packets", message
    )
    if match is not None:
        direction = _DIRECTION_LABELS[match.group(2)]
        return f"已提取 {match.group(1)} 个{direction} TCP 报文"

    match = re.fullmatch(
        r"Completed (download|upload|both) TCP extraction", message
    )
    if match is not None:
        direction = _DIRECTION_LABELS[match.group(1)]
        return f"{direction} TCP 报文提取完成"

    if any("\u4e00" <= character <= "\u9fff" for character in message):
        return message
    return "分析处理中"


def _normalize_capture_path(value: str) -> str:
    expanded = str(Path(value).expanduser())
    if is_absolute_path(expanded):
        return expanded
    return str(Path(expanded).resolve())


@app.callback()
def main() -> None:
    """PacketMaster TCP 测速不达标诊断。"""


async def run_diagnosis(
    *,
    pcap_path: str,
    standard: float,
    actual: float,
    target: Target,
    request_id: str,
    settings: Settings,
) -> DiagnosisOutcome:
    def progress(event: DiagnosisProgress) -> None:
        if event.message:
            typer.echo(f"[进度] {_localize_progress_message(event.message)}")

    return await DiagnosisService(settings).run(
        pcap_path=pcap_path,
        standard=standard,
        actual=actual,
        target=target,
        request_id=request_id,
        progress_handler=progress,
    )


@app.command()
def diagnose(
    pcap_path: Annotated[str, typer.Argument(help="pcap/pcapng 路径")],
    standard: Annotated[float, typer.Option("--standard", min=0.000001)],
    actual: Annotated[float, typer.Option("--actual", min=0.000001)],
    target: Annotated[Target, typer.Option("--target")] = Target.DOWNLOAD,
    output_dir: Annotated[str | None, typer.Option("--output-dir")] = None,
    keep_artifacts: Annotated[bool, typer.Option("--keep-artifacts")] = False,
) -> None:
    try:
        settings = Settings.load()
        artifact_manager = ArtifactManager(
            settings.artifact_root, settings.artifact_ttl_hours
        )
        artifact_manager.cleanup_expired(time.time())
        request_id = create_request_id()
        destination = (
            Path(output_dir).expanduser().resolve()
            if output_dir is not None
            else (settings.artifact_root / request_id).expanduser().resolve()
        )
        raw_outcome = asyncio.run(
            run_diagnosis(
                pcap_path=_normalize_capture_path(pcap_path),
                standard=standard,
                actual=actual,
                target=target,
                request_id=request_id,
                settings=settings,
            )
        )
        outcome = (
            raw_outcome
            if isinstance(raw_outcome, DiagnosisOutcome)
            else DiagnosisOutcome(report=raw_outcome)
        )
        report = outcome.report
        report_path = write_report(report, destination / "report.json")
        if keep_artifacts:
            artifact_manager.mark_keep(artifact_manager.create(request_id))
        typer.echo(render_terminal(report))
        typer.echo(f"JSON 报告: {report_path}")
        if outcome.error is not None:
            raise outcome.error
    except AppError as exc:
        typer.echo(json.dumps(exc.to_dict(), ensure_ascii=False), err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        error = AppError(
            code="CLI_FAILED",
            message="PacketMaster CLI failed",
            recoverable=False,
            suggested_action="Inspect local configuration and retry.",
            details={"exception_type": exc.__class__.__name__},
        )
        typer.echo(json.dumps(error.to_dict(), ensure_ascii=False), err=True)
        raise typer.Exit(code=1) from exc


async def _answer_chat_question(
    session: ChatSession, settings: Settings, question: str
) -> tuple[str, dict[str, object] | None]:
    session.state.question = question
    adapter = RealAnalyzerAdapter(
        artifact_root=settings.artifact_root,
        pipeline_script=settings.speed_analyzer_script,
        tshark_path=settings.tshark_path,
        evidence_timeout_seconds=settings.evidence_timeout_seconds,
    )
    server = create_server(adapter)
    async with SpeedMCPClient(server) as client:
        graph = build_chat_graph(
            mcp_client=client,
            diagnosis_model=DiagnosisModel(settings=settings),
        )
        result = await graph.ainvoke({"session": session.state})
    error = result.get("error")
    if error:
        return "问答暂时失败：" + str(error.get("message", "未知错误")), error
    answer = result.get("answer")
    if answer is None:
        return "问答未生成有效回答。", {"code": "CHAT_EMPTY_ANSWER"}
    return answer.answer, None


def _chat_confirmation(intent, path_registry) -> str:
    target = intent.target.value if intent.target else Target.DOWNLOAD.value
    target_label = {
        "download": "下载",
        "upload": "上行",
        "both": "上行和下载",
    }[target]
    capture_name = "缺失"
    if intent.capture is not None and path_registry is not None:
        try:
            capture_name = Path(path_registry.resolve(intent.capture)).name
        except ValueError:
            capture_name = "无法解析"
    return (
        "已识别参数：\n"
        f"- 报文文件：{capture_name}\n"
        f"- 标准带宽：{intent.standard_bandwidth_mbps or '缺失'} Mbps\n"
        f"- 实际带宽：{intent.actual_bandwidth_mbps or '缺失'} Mbps\n"
        f"- 分析方向：{target_label}\n"
        "提示：未填写带宽单位时默认按 Mbps 解释。\n"
        "请确认是否启动分析？(Y/N)"
    )


def _intent_clarification(intent) -> str | None:
    if intent.ambiguities:
        return "我发现信息存在歧义：" + "；".join(intent.ambiguities) + "。请更正。"
    prompts = {
        "capture": "请提供要分析的 pcap 或 pcapng 报文文件路径。",
        "standard_bandwidth_mbps": (
            "请告诉我标准带宽，例如 1000 Mbps；不写单位时默认按 Mbps。"
        ),
        "actual_bandwidth_mbps": (
            "请告诉我实际测速带宽，例如 600 Mbps；不写单位时默认按 Mbps。"
        ),
    }
    for field in intent.missing_fields:
        if field in prompts:
            return prompts[field]
    return None


def _answer_general_chat(
    session: ChatSession, settings: Settings, question: str
) -> str:
    session.state.question = question
    model = DiagnosisModel(settings=settings)
    answer = asyncio.run(
        model.general_chat(
            question,
            session.state.conversation_summary,
            session.state.conversation_turns,
        )
    )
    session.append_turn(question, answer.answer)
    return answer.answer


@app.command()
def chat() -> None:
    """启动 PacketMaster 持续对话诊断。"""

    settings = Settings.load()
    session = ChatSession(
        ChatSessionState(session_id=create_request_id()),
        ArtifactManager(settings.artifact_root, settings.artifact_ttl_hours),
    )
    path_registry = None
    typer.echo("PacketMaster 对话模式。输入 /help 查看命令，/quit 退出。")
    try:
        while True:
            prompt = "PacketMaster> " if session.state.analysis_id else "你> "
            try:
                raw = builtins.input(prompt)
            except (EOFError, KeyboardInterrupt):
                typer.echo("\n已退出 PacketMaster。")
                return
            command = parse_command(raw)
            if command is not None:
                if command.command in {ChatCommand.EMPTY}:
                    continue
                if command.command is ChatCommand.QUIT:
                    typer.echo("已退出 PacketMaster。")
                    return
                if command.command is ChatCommand.HELP:
                    typer.echo(
                        "/new 新建任务  /report 查看报告  /evidence 查看关键证据\n"
                        "/save 查看报告路径  /quit 退出"
                    )
                    continue
                if command.command is ChatCommand.UNKNOWN:
                    typer.echo("未知命令，请输入 /help。")
                    continue
                if command.command is ChatCommand.NEW:
                    session.reset()
                    path_registry = None
                    typer.echo("已新建会话，请描述新的报文诊断任务。")
                    continue
                if command.command is ChatCommand.REPORT:
                    if session.state.report is None:
                        typer.echo("当前还没有诊断报告。")
                    else:
                        report_path = (
                            Path(session.state.report_path)
                            if session.state.report_path
                            else None
                        )
                        typer.echo(
                            render_chat_report(session.state.report, report_path)
                        )
                    continue
                if command.command is ChatCommand.SAVE:
                    report_location = session.state.report_path or "当前还没有报告"
                    typer.echo(f"JSON 报告：{report_location}")
                    continue
                if command.command is ChatCommand.EVIDENCE:
                    evidence = (
                        session.state.report.key_evidence
                        if session.state.report
                        else []
                    )
                    typer.echo(json.dumps(evidence[:20], ensure_ascii=False, indent=2))
                    continue

            route = route_conversation(
                raw,
                has_analysis=session.state.analysis_id is not None,
                has_pending_intent=session.state.pending_intent is not None,
            )
            if route is ConversationRoute.GENERAL:
                try:
                    typer.echo(_answer_general_chat(session, settings, raw))
                except Exception as exc:
                    typer.echo(f"对话暂时失败，请稍后重试：{exc}")
                continue

            if session.state.analysis_id is None:
                try:
                    model = DiagnosisModel(settings=settings)
                    intent, extraction = asyncio.run(
                        model.parse_intent(raw, session.state.pending_intent)
                    )
                    if path_registry is None:
                        path_registry = extraction.registry
                    else:
                        path_registry.extend(extraction.registry)
                    session.state.pending_intent = intent
                except Exception as exc:
                    typer.echo(f"参数抽取失败，请补充完整参数后重试：{exc}")
                    continue
                clarification = _intent_clarification(intent)
                if clarification:
                    typer.echo(clarification)
                    continue
                typer.echo(_chat_confirmation(intent, path_registry))
                confirmed = builtins.input("确认> ").strip().casefold()
                if confirmed not in {"y", "yes", "是", "确认"}:
                    typer.echo("已取消启动，可继续修正参数。")
                    continue
                if path_registry is None or intent.capture is None:
                    typer.echo("报文路径无效，请重新输入。")
                    continue
                request_id = create_request_id()
                try:
                    intent.confirmed = True
                    outcome = asyncio.run(
                        run_diagnosis(
                            pcap_path=path_registry.resolve(intent.capture),
                            standard=intent.standard_bandwidth_mbps,
                            actual=intent.actual_bandwidth_mbps,
                            target=intent.target or Target.DOWNLOAD,
                            request_id=request_id,
                            settings=settings,
                        )
                    )
                    destination = (settings.artifact_root / request_id).resolve()
                    report_path = write_report(
                        outcome.report, destination / "report.json"
                    )
                    session.state.analysis_id = request_id
                    session.state.target = intent.target or Target.DOWNLOAD
                    session.state.standard_bandwidth_mbps = (
                        intent.standard_bandwidth_mbps
                    )
                    session.state.actual_bandwidth_mbps = intent.actual_bandwidth_mbps
                    session.state.report = outcome.report
                    session.state.report_path = str(report_path)
                    session.state.diagnosis_context = (
                        outcome.context.model_dump(mode="json")
                        if outcome.context is not None
                        else {}
                    )
                    session.attach_analysis(request_id)
                    typer.echo(render_chat_report(outcome.report, report_path))
                    if outcome.error:
                        typer.echo("诊断已降级完成，请注意报告限制。")
                except Exception as exc:
                    typer.echo(f"诊断失败：{exc}")
                continue

            answer, _ = asyncio.run(_answer_chat_question(session, settings, raw))
            session.append_turn(raw, answer)
            typer.echo(answer)
    finally:
        session.finish()


if __name__ == "__main__":
    app()
