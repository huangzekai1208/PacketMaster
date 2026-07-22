"""Structured errors exposed by PacketMaster interfaces."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """An actionable error that callers can catch without parsing its text."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        recoverable: bool,
        suggested_action: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recoverable = recoverable
        self.suggested_action = suggested_action
        self.details = details or {}
