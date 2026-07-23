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
        f"置信度: {report.confidence.value}",
    ]
    if report.limitations:
        lines.append("限制: " + "；".join(report.limitations[:10]))
    return "\n".join(lines)
