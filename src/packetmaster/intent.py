"""从自然语言稳定提取诊断参数、带宽单位和本机路径引用。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from packetmaster.domain import DiagnosisIntent, PathReference, Target

_CAPTURE_SUFFIX = r"(?:pcapng|pcap)"
_QUOTED_PATH = re.compile(
    rf"(?P<quote>['\"])(?P<path>.*?\.{_CAPTURE_SUFFIX})(?P=quote)", re.IGNORECASE
)
_WINDOWS_PATH = re.compile(
    rf"(?P<path>[A-Za-z]:[\\/][^\"'，。；,;!?\n]*?\.{_CAPTURE_SUFFIX})",
    re.IGNORECASE,
)
_POSIX_PATH = re.compile(
    rf"(?P<path>(?:/|\.\.?/)[^\"'，。；,;!?\n]*?\.{_CAPTURE_SUFFIX})",
    re.IGNORECASE,
)
_BARE_PATH = re.compile(
    rf"(?<![\w./-])(?P<path>[\w\u0080-\uffff][^\"'，。；,;!?\n]*?\.{_CAPTURE_SUFFIX})",
    re.IGNORECASE,
)

_UNIT_MULTIPLIERS = {
    "mbps": 1.0,
    "mb/s": 1.0,
    "m": 1.0,
    "兆": 1.0,
    "gbps": 1_000.0,
    "gb/s": 1_000.0,
    "g": 1_000.0,
    "千兆": 1_000.0,
    "kbps": 0.001,
    "kb/s": 0.001,
    "k": 0.001,
}
_BANDWIDTH_UNIT = r"(?:gbps?|gb/s|g|mbps?|mb/s|m|kbps?|kb/s|k|千兆|兆)"
_STANDARD_BANDWIDTH = re.compile(
    rf"标准(?:带宽|速率)?\s*[:：=]?\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>{_BANDWIDTH_UNIT})?",
    re.IGNORECASE,
)
_ACTUAL_BANDWIDTH = re.compile(
    rf"(?:实际|实测|当前)(?:带宽|速率)?\s*[:：=]?\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>{_BANDWIDTH_UNIT})?",
    re.IGNORECASE,
)
_SHORT_BANDWIDTH = re.compile(
    rf"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>{_BANDWIDTH_UNIT})?\s*$",
    re.IGNORECASE,
)


@dataclass
class PathRegistry:
    """Local-only mapping between opaque model tokens and capture paths."""

    _paths: dict[str, str] = field(default_factory=dict)

    def register(self, value: str) -> PathReference:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            local = Path.cwd() / candidate
            sample = Path.cwd() / "samples" / candidate.name
            candidate = next(
                (item for item in (local, sample) if item.is_file()), local
            )
        normalized = str(candidate.resolve())
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8]
        placeholder = f"capture_{digest}"
        self._paths[placeholder] = normalized
        return PathReference(placeholder=placeholder)

    def resolve(self, reference: PathReference) -> str:
        try:
            return self._paths[reference.placeholder]
        except KeyError as exc:
            raise ValueError("unknown capture path reference") from exc

    def values(self) -> dict[str, str]:
        return dict(self._paths)

    def extend(self, other: PathRegistry) -> None:
        """Retain path references found in earlier natural-language turns."""

        self._paths.update(other.values())


@dataclass(frozen=True)
class PathExtraction:
    sanitized_text: str
    references: tuple[PathReference, ...]
    registry: PathRegistry


def extract_explicit_bandwidth(text: str) -> dict[str, float | str]:
    """Extract unambiguous standard/actual bandwidth values locally."""
    values: dict[str, float | str] = {}
    for key, pattern in (
        ("standard", _STANDARD_BANDWIDTH),
        ("actual", _ACTUAL_BANDWIDTH),
    ):
        match = pattern.search(text)
        if match:
            values[f"{key}_bandwidth_value"] = float(match.group("value"))
            values[f"{key}_bandwidth_unit"] = match.group("unit") or "Mbps"
    return values


def extract_contextual_values(
    text: str, previous: DiagnosisIntent | None
) -> dict[str, float | str | Target]:
    """Interpret a short reply using the next missing intent field."""

    values: dict[str, float | str | Target] = {}
    lowered = text.casefold()
    if "上行+下载" in lowered or "上传+下载" in lowered or "双向" in lowered:
        values["target"] = Target.BOTH
    elif "上行" in lowered or "上传" in lowered:
        values["target"] = Target.UPLOAD
    elif "下载" in lowered:
        values["target"] = Target.DOWNLOAD

    match = _SHORT_BANDWIDTH.fullmatch(text)
    if match is None or previous is None:
        return values
    if previous.standard_bandwidth_mbps is None:
        prefix = "standard"
    elif previous.actual_bandwidth_mbps is None:
        prefix = "actual"
    else:
        return values
    values[f"{prefix}_bandwidth_value"] = float(match.group("value"))
    values[f"{prefix}_bandwidth_unit"] = match.group("unit") or "Mbps"
    return values


def _clean_path(value: str) -> str:
    return value.strip().strip("\"'").rstrip("。；,;!?，")


def extract_capture_paths(text: str) -> PathExtraction:
    """Replace local pcap/pcapng paths with opaque references."""

    registry = PathRegistry()
    matches: list[tuple[int, int, str]] = []
    occupied: list[tuple[int, int]] = []
    for pattern in (_QUOTED_PATH, _WINDOWS_PATH, _POSIX_PATH, _BARE_PATH):
        for match in pattern.finditer(text):
            start, end = match.span("path")
            if any(start < right and end > left for left, right in occupied):
                continue
            value = _clean_path(match.group("path"))
            if not value.lower().endswith((".pcap", ".pcapng")):
                continue
            matches.append((start, end, value))
            occupied.append((start, end))

    matches.sort(key=lambda item: item[0])
    references: list[PathReference] = []
    chunks: list[str] = []
    cursor = 0
    for start, end, value in matches:
        reference = registry.register(value)
        references.append(reference)
        chunks.extend((text[cursor:start], reference.placeholder))
        cursor = end
    chunks.append(text[cursor:])
    return PathExtraction("".join(chunks), tuple(references), registry)


def normalize_bandwidth(value: float, unit: str | None) -> float:
    """Convert common bandwidth units to Mbps deterministically."""

    normalized = (unit or "Mbps").strip().lower().replace("兆比特/秒", "兆")
    normalized = normalized.replace("gigabit", "g").replace("megabit", "m")
    normalized = normalized.replace("gb/s", "gbps").replace("mb/s", "mbps")
    try:
        multiplier = _UNIT_MULTIPLIERS[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported bandwidth unit: {unit}") from exc
    result = value * multiplier
    if result <= 0:
        raise ValueError("bandwidth must be positive")
    return result


def default_target(target: Target | None) -> Target:
    return target or Target.DOWNLOAD


def merge_intent(
    previous: DiagnosisIntent | None, current: DiagnosisIntent
) -> DiagnosisIntent:
    """Merge non-empty fields while preserving explicit ambiguity."""

    if previous is None:
        merged = current.model_copy(deep=True)
    else:
        values = previous.model_dump()
        for key, value in current.model_dump().items():
            if value not in (None, [], {}, ""):
                values[key] = value
        merged = DiagnosisIntent.model_validate(values)
    if merged.target is None and not merged.ambiguities:
        merged.target = Target.DOWNLOAD
    if merged.standard_bandwidth_mbps is None and merged.standard_bandwidth_value:
        merged.standard_bandwidth_mbps = normalize_bandwidth(
            merged.standard_bandwidth_value, merged.standard_bandwidth_unit
        )
    if merged.actual_bandwidth_mbps is None and merged.actual_bandwidth_value:
        merged.actual_bandwidth_mbps = normalize_bandwidth(
            merged.actual_bandwidth_value, merged.actual_bandwidth_unit
        )
    missing: list[str] = []
    if merged.capture is None:
        missing.append("capture")
    if merged.standard_bandwidth_mbps is None:
        missing.append("standard_bandwidth_mbps")
    if merged.actual_bandwidth_mbps is None:
        missing.append("actual_bandwidth_mbps")
    merged.missing_fields = missing
    # A complete intent is only ready for confirmation. The CLI sets this to
    # true after an explicit user acknowledgement, never as a side effect of
    # model extraction or a natural-language correction.
    merged.confirmed = False
    return merged
