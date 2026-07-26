"""Runtime settings loaded from local defaults and environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from packetmaster import config_local as _local_config
except ModuleNotFoundError as exc:
    if exc.name != "packetmaster.config_local":
        raise
    LOCAL_MODEL_API_KEY: str | None = None
    LOCAL_MODEL_BASE_URL: str | None = None
    LOCAL_MODEL_NAME = "gpt-4.1-mini"
    LOCAL_STRUCTURED_OUTPUT_METHOD = "auto"
else:
    LOCAL_MODEL_API_KEY = _local_config.MODEL_API_KEY
    LOCAL_MODEL_BASE_URL = _local_config.MODEL_BASE_URL
    LOCAL_MODEL_NAME = _local_config.MODEL_NAME
    LOCAL_STRUCTURED_OUTPUT_METHOD = _local_config.MODEL_STRUCTURED_OUTPUT_METHOD


class Settings(BaseSettings):
    """Local defaults that uppercase environment variables can override."""

    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    model_base_url: str | None = LOCAL_MODEL_BASE_URL
    model_api_key: SecretStr | None = Field(
        default=(SecretStr(LOCAL_MODEL_API_KEY) if LOCAL_MODEL_API_KEY else None),
        repr=False,
    )
    model_name: str = LOCAL_MODEL_NAME
    model_structured_output_method: Literal[
        "auto", "json_schema", "function_calling", "json_mode"
    ] = LOCAL_STRUCTURED_OUTPUT_METHOD
    model_timeout_seconds: int = Field(default=120, gt=0)
    evidence_timeout_seconds: int = Field(default=120, gt=0, le=600)
    speed_analyzer_mode: str = "real"
    speed_analyzer_script: Path | None = None
    artifact_root: Path = Path("artifacts")
    artifact_ttl_hours: int = Field(default=24, gt=0)
    tshark_path: str = "tshark"
    max_inspection_rounds: int = Field(default=3, ge=1, le=3)
    web_database_path: Path = Path("artifacts/packetmaster-web.sqlite")
    web_allowed_capture_roots: list[Path] = Field(
        default_factory=lambda: [Path.cwd()]
    )
    web_host: Literal["127.0.0.1"] = "127.0.0.1"
    web_port: int = Field(default=8765, ge=1024, le=65535)

    @classmethod
    def load(cls) -> Settings:
        return cls()
