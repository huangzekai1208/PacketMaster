"""CLI 与 Web 共用的报文分析进度消息中文化。"""

from __future__ import annotations

import re

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


def localize_progress_message(message: str | None) -> str:
    """将受控流水线进度转换为中文，未知英文不直接暴露给页面。"""

    if not message:
        return "正在分析报文"
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

    match = re.fullmatch(r"Completed (download|upload|both) TCP extraction", message)
    if match is not None:
        direction = _DIRECTION_LABELS[match.group(1)]
        return f"{direction} TCP 报文提取完成"

    if any("\u4e00" <= character <= "\u9fff" for character in message):
        return message
    return "分析处理中"
