"""Terminal and atomic JSON reporting for PacketMaster."""

from __future__ import annotations

import json
from pathlib import Path

from packetmaster.domain import DiagnosticReport


def write_report(report: DiagnosticReport, path: Path) -> Path:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def render_terminal(report: DiagnosticReport) -> str:
    coverage = report.coverage_summary
    lines = [
        f"分析方向: {report.target.value}",
        f"带宽达标率: {report.achievement_ratio_pct:.2f}%",
        f"主要原因: {report.primary_cause}",
        (
            "覆盖范围: "
            f"测速包 {coverage.speed_packets_analyzed}, "
            f"complete={coverage.complete}, truncated={coverage.truncated}"
        ),
        f"关键证据: {len(report.key_evidence)} 条",
        f"置信度: {report.confidence:.2f}%",
    ]
    if report.limitations:
        lines.append("限制: " + "；".join(report.limitations[:10]))
    return "\n".join(lines)


def _render_evidence_reference(reference: dict[str, object]) -> str:
    parts = [f"{key}={value}" for key, value in reference.items()]
    return "，".join(parts)


def render_chat_report(
    report: DiagnosticReport, report_path: Path | None = None
) -> str:
    """Render the complete report deterministically for the chat terminal."""

    coverage = report.coverage_summary
    coverage_text = "完整" if coverage.complete else "不完整"
    truncation_text = "未截断" if not coverage.truncated else "已截断"
    lines = [
        "PacketMaster 诊断报告",
        (
            f"本次分析方向为{report.target.value}，实际带宽为 "
            f"{report.actual_bandwidth_mbps:g} Mbps，标准带宽为 "
            f"{report.standard_bandwidth_mbps:g} Mbps，达标率为 "
            f"{report.achievement_ratio_pct:.2f}%。"
        ),
        f"主要原因：{report.primary_cause}（置信度 {report.confidence:.2f}%）。",
        (
            "报文覆盖：已识别 "
            f"{coverage.total_packets_seen} 个报文，分析 "
            f"{coverage.speed_packets_analyzed} 个测速报文；"
            f"覆盖{coverage_text}，{truncation_text}。"
        ),
    ]
    if report.candidate_causes:
        lines.append("候选原因：")
        for index, candidate in enumerate(report.candidate_causes, 1):
            lines.append(
                f"{index}. {candidate.cause}（置信度 "
                f"{candidate.confidence:.2f}%）"
            )
            if candidate.supporting_evidence:
                lines.append("   支持证据：" + "；".join(candidate.supporting_evidence))
            if candidate.contradicting_evidence:
                lines.append(
                    "   反向证据：" + "；".join(candidate.contradicting_evidence)
                )
            if candidate.missing_evidence:
                lines.append("   缺失证据：" + "；".join(candidate.missing_evidence))
            if candidate.suggestion:
                lines.append("   建议：" + candidate.suggestion)
    if report.key_evidence:
        lines.append("关键证据：")
        for index, evidence in enumerate(report.key_evidence, 1):
            evidence_type = evidence.get("evidence_type", "未分类证据")
            total = evidence.get("total")
            lines.append(f"{index}. 证据类型：{evidence_type}；命中数量：{total}。")
            references = evidence.get("references")
            if isinstance(references, list):
                for reference in references:
                    if isinstance(reference, dict) and reference:
                        lines.append(
                            "   引用：" + _render_evidence_reference(reference)
                        )
    if report.limitations:
        lines.append("限制：" + "；".join(report.limitations))
    if report.troubleshooting_steps:
        lines.append("排查步骤：")
        lines.extend(
            f"{index}. {step}"
            for index, step in enumerate(report.troubleshooting_steps, 1)
        )
    if report.optimization_suggestions:
        lines.append("优化建议：" + "；".join(report.optimization_suggestions))
    if report_path is not None:
        lines.append(f"JSON 报告：{report_path}")
    return "\n".join(lines)
