"""Bounded CLI chat state and safe model-context projection."""

from __future__ import annotations

import re
from typing import Any

from packetmaster.domain import ChatModelContext, ChatSessionState

_SENSITIVE_KEYS = re.compile(
    r"(?:api[_-]?key|authorization|token|password|payload|raw[_-]?packet|"
    r"per[_-]?packet|full[_-]?log|absolute[_-]?path|pcap[_-]?path)",
    re.IGNORECASE,
)
_PATH_VALUE = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\|~[/\\])")


def _strip_sensitive(value: Any) -> Any:
    """Recursively remove secrets, payloads, logs, and local paths."""

    if isinstance(value, dict):
        return {
            str(key): _strip_sensitive(item)
            for key, item in value.items()
            if not _SENSITIVE_KEYS.search(str(key))
        }
    if isinstance(value, list):
        return [_strip_sensitive(item) for item in value[:32]]
    if isinstance(value, str) and _PATH_VALUE.match(value):
        return "<本地路径已隐藏>"
    return value


def build_model_context(state: ChatSessionState) -> ChatModelContext:
    """Build the bounded, privacy-filtered projection for a model call."""

    return state.model_context()


def validate_question(question: str) -> str:
    value = question.strip()
    if not value:
        raise ValueError("question must not be empty")
    if len(value) > 2_000:
        raise ValueError("question must not exceed 2000 characters")
    return value

