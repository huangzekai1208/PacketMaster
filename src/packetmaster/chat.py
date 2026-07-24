"""Bounded CLI chat state and safe model-context projection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from packetmaster.artifacts import ArtifactManager, ArtifactPaths
from packetmaster.domain import ChatModelContext, ChatSessionState, ConversationTurn

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


class ChatCommand(StrEnum):
    NEW = "new"
    REPORT = "report"
    EVIDENCE = "evidence"
    SAVE = "save"
    HELP = "help"
    QUIT = "quit"
    UNKNOWN = "unknown"
    EMPTY = "empty"


@dataclass(frozen=True)
class ParsedCommand:
    command: ChatCommand
    argument: str = ""


def parse_command(value: str) -> ParsedCommand | None:
    """Parse slash commands without sending them to a model."""

    text = value.strip()
    if not text:
        return ParsedCommand(ChatCommand.EMPTY)
    if not text.startswith("/"):
        return None
    parts = text[1:].split(maxsplit=1)
    name = parts[0].casefold()
    argument = parts[1].strip() if len(parts) == 2 else ""
    try:
        command = ChatCommand(name)
    except ValueError:
        command = ChatCommand.UNKNOWN
    return ParsedCommand(command, argument)


class ChatSession:
    """Own chat state and artifact activity for one CLI process."""

    max_turns = 8
    max_summary_bytes = 8_000

    def __init__(
        self,
        state: ChatSessionState,
        artifact_manager: ArtifactManager | None = None,
    ) -> None:
        self.state = state
        self._artifact_manager = artifact_manager
        self._active_paths: ArtifactPaths | None = None

    def attach_analysis(self, request_id: str) -> ArtifactPaths | None:
        """Mark an analysis active after the analyzer has created its artifacts."""

        if self._artifact_manager is None:
            return None
        self._active_paths = self._artifact_manager.create(request_id)
        self._artifact_manager.mark_active(self._active_paths)
        return self._active_paths

    def append_turn(self, question: str, answer: str) -> None:
        turn = ConversationTurn(question=validate_question(question), answer=answer)
        turns = [*self.state.conversation_turns, turn]
        if len(turns) > self.max_turns:
            archived = turns[:-self.max_turns]
            summary = "\n".join(
                f"问：{item.question}\n答：{item.answer}" for item in archived
            )
            summary = _bounded_utf8(
                f"{self.state.conversation_summary}\n{summary}".strip(),
                self.max_summary_bytes,
            )
            self.state.conversation_summary = summary
            turns = turns[-self.max_turns :]
        self.state.conversation_turns = turns

    def reset(self) -> None:
        self.finish()
        session_id = self.state.session_id
        self.state = ChatSessionState(session_id=session_id)

    def finish(self) -> None:
        if self._active_paths is not None and self._artifact_manager is not None:
            self._artifact_manager.mark_complete(self._active_paths)
        self._active_paths = None


def _bounded_utf8(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[-limit:].decode("utf-8", errors="ignore")
