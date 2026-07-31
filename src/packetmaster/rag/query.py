"""从诊断状态构建确定性、字段白名单化的知识检索查询。"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from packetmaster.context import DiagnosisContext
from packetmaster.domain import ChatModelContext, HypothesisBatch
from packetmaster.rag.contracts import KnowledgeQuery

_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|authorization|token|password|payload|raw[_-]?packet|"
    r"full[_-]?log|absolute[_-]?path|pcap[_-]?path|log[_-]?path)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|token|password)\s*[:=]\s*\S+"
)
_LOCAL_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/][^\s，。；,;]+|/(?:Users|home|private|tmp|var)/[^\s，。；,;]+)"
)
_EVENT_TERMS = {
    "retransmission_count": ("retransmission", "重传"),
    "duplicate_ack_count": ("duplicate_ack", "重复ACK"),
    "out_of_order_count": ("out_of_order", "乱序"),
    "zero_window_count": ("zero_window", "零窗口"),
    "window_full_count": ("window_full", "接收窗口满"),
}


def _safe_question(value: str | None) -> str:
    if not value:
        return ""
    cleaned = _SECRET_ASSIGNMENT.sub("<敏感配置已隐藏>", value)
    cleaned = _LOCAL_PATH.sub("<本地路径已隐藏>", cleaned)
    return cleaned[:2_000]


def _feature_items(value: Any, *, prefix: str = "") -> list[tuple[str, object]]:
    items: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key in sorted(value):
            name = str(key)[:128]
            if _SENSITIVE_KEY.search(name):
                continue
            child_prefix = f"{prefix}.{name}" if prefix else name
            items.extend(_feature_items(value[key], prefix=child_prefix))
    elif isinstance(value, list):
        for index, item in enumerate(value[:8]):
            items.extend(_feature_items(item, prefix=f"{prefix}[{index}]"))
    elif isinstance(value, str | bool | int | float) or value is None:
        if prefix and not (isinstance(value, str) and _LOCAL_PATH.search(value)):
            bounded = value[:128] if isinstance(value, str) else value
            items.append((prefix[-128:], bounded))
    return items


def _ratio_bin(value: float) -> str:
    if value < 10:
        return "0-10pct"
    if value < 30:
        return "10-30pct"
    if value < 60:
        return "30-60pct"
    if value < 90:
        return "60-90pct"
    return "90pct-plus"


def _rtt_bin(value: float) -> str:
    if value < 20:
        return "low"
    if value < 80:
        return "medium"
    return "high"


class KnowledgeQueryBuilder:
    def build_general_chat(self, question: str) -> KnowledgeQuery | None:
        """Build a bounded query for a conversation without an analysis report."""
        safe_question = _safe_question(question)
        if not safe_question:
            return None
        identity = json.dumps(
            {"scope": "general_chat", "question": safe_question},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return KnowledgeQuery(
            query_id="ragq-"
            + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
            query_text=f"用户问题 {safe_question}",
        )

    def build_chat(self, context: ChatModelContext) -> KnowledgeQuery | None:
        question = _safe_question(context.question)
        if not question:
            return None
        feature_pairs = _feature_items(context.diagnosis_context)
        features: dict[str, object] = {}
        for key, value in feature_pairs:
            short_key = key.split(".")[-1].split("[")[0]
            if short_key not in features and len(features) < 64:
                features[short_key] = value
        report = context.report
        raw_candidates = report.get("candidate_causes", [])
        candidate_causes = [
            str(item.get("cause", ""))[:1_000]
            for item in raw_candidates[:32]
            if isinstance(item, dict) and item.get("cause")
        ]
        primary = report.get("primary_cause")
        if isinstance(primary, str) and primary and primary != "unresolved":
            candidate_causes = list(dict.fromkeys([primary, *candidate_causes]))[:32]
        ratio_value = report.get("achievement_ratio_pct")
        ratio = (
            float(ratio_value)
            if isinstance(ratio_value, int | float)
            and not isinstance(ratio_value, bool)
            else None
        )
        keywords: list[str] = []
        searchable = json.dumps(
            {"question": question, "features": features},
            ensure_ascii=False,
            sort_keys=True,
        ).casefold()
        for metric, terms in _EVENT_TERMS.items():
            if metric.casefold() in searchable or any(
                term.casefold() in searchable for term in terms
            ):
                keywords.extend(terms)
        identity = json.dumps(
            {
                "analysis_id": context.analysis_id,
                "direction": context.target.value,
                "ratio": ratio,
                "question": question,
                "features": features,
                "causes": candidate_causes,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        query_id = "ragq-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return KnowledgeQuery(
            query_id=query_id,
            analysis_id=context.analysis_id,
            direction=context.target,
            achievement_ratio_pct=ratio,
            query_text=(
                f"方向 {context.target.value}；"
                f"用户问题 {question}；"
                + "；".join(f"候选原因 {item}" for item in candidate_causes)
            )[:4_000],
            keywords=list(dict.fromkeys(keywords))[:64],
            candidate_causes=candidate_causes,
            global_features=features,
        )

    def build(
        self,
        context: DiagnosisContext,
        hypotheses: HypothesisBatch | None = None,
        *,
        question: str | None = None,
        environment_tags: dict[str, str] | None = None,
    ) -> KnowledgeQuery | None:
        candidate_causes = [
            item.cause[:1_000] for item in (hypotheses.hypotheses if hypotheses else [])
        ][:32]
        missing_evidence = [
            evidence[:1_000]
            for item in (hypotheses.hypotheses if hypotheses else [])
            for evidence in item.missing_evidence
        ][:32]
        feature_pairs = _feature_items(
            {
                "global": context.global_metrics,
                "flows": context.flow_metrics,
                "intervals": context.anomaly_intervals,
                "syn": context.syn_options,
            }
        )
        features: dict[str, object] = {}
        for key, value in feature_pairs:
            short_key = key.split(".")[-1].split("[")[0]
            if short_key not in features and len(features) < 64:
                features[short_key] = value
        keywords: list[str] = []
        has_anomaly = False
        for metric, terms in _EVENT_TERMS.items():
            values = [
                value
                for key, value in feature_pairs
                if key.endswith(metric) and isinstance(value, int | float)
            ]
            if any(value > 0 for value in values):
                has_anomaly = True
                keywords.extend(terms)
        ratio = float(context.bandwidth.get("achievement_ratio_pct", 0.0))
        keywords.append(f"achievement:{_ratio_bin(ratio)}")
        rtt = features.get("rtt_ms")
        if isinstance(rtt, int | float):
            keywords.append(f"rtt:{_rtt_bin(float(rtt))}")
        if isinstance(features.get("window_min"), int | float):
            if float(features["window_min"]) <= 0:
                keywords.extend(("receive_window", "接收窗口"))
                has_anomaly = True
        safe_question = _safe_question(question)
        has_signal = bool(
            has_anomaly or candidate_causes or safe_question or context.syn_options
        )
        if not has_signal:
            return None
        safe_environment = {
            str(key)[:128]: str(value)[:128]
            for key, value in sorted((environment_tags or {}).items())
            if not _SENSITIVE_KEY.search(str(key))
            and not _LOCAL_PATH.search(str(value))
        }
        keywords = list(dict.fromkeys(item[:128] for item in keywords))[:64]
        parts = [
            f"方向 {context.target.value}",
            f"带宽达标率 {_ratio_bin(ratio)}",
            *(f"异常 {item}" for item in keywords if ":" not in item),
            *(f"候选原因 {item}" for item in candidate_causes),
        ]
        if safe_question:
            parts.append(f"用户问题 {safe_question}")
        query_text = "；".join(parts)[:4_000]
        identity = json.dumps(
            {
                "analysis_id": context.analysis_id,
                "direction": context.target.value,
                "ratio": ratio,
                "keywords": keywords,
                "causes": candidate_causes,
                "missing": missing_evidence,
                "features": features,
                "environment": safe_environment,
                "question": safe_question,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        query_id = "ragq-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return KnowledgeQuery(
            query_id=query_id,
            analysis_id=context.analysis_id,
            direction=context.target,
            achievement_ratio_pct=ratio,
            query_text=query_text,
            keywords=keywords,
            candidate_causes=candidate_causes,
            missing_evidence=missing_evidence,
            global_features=features,
            environment_tags=safe_environment,
        )
