"""Runtime settings loaded from local defaults and environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from packetmaster.rag.contracts import RagMode

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
    rag_enabled: bool = False
    rag_mode: RagMode = RagMode.SHADOW
    knowledge_database_path: Path = Field(
        default=Path("artifacts/knowledge/packetmaster-knowledge.sqlite"),
        exclude=True,
        repr=False,
    )
    embedding_provider: Literal["local"] = "local"
    embedding_model: str = Field(
        default="intfloat/multilingual-e5-small", min_length=1, max_length=256
    )
    embedding_model_path: Path | None = Field(
        default=None, exclude=True, repr=False
    )
    rag_keyword_top_k: int = Field(default=20, ge=1, le=100)
    rag_vector_top_k: int = Field(default=20, ge=1, le=100)
    rag_final_top_k: int = Field(default=8, ge=1, le=8)
    rag_max_context_bytes: int = Field(default=24_576, ge=1_024, le=24_576)
    rag_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    rag_max_chunks: int = Field(default=25_000, ge=1, le=25_000)

    @property
    def effective_rag_mode(self) -> RagMode:
        return self.rag_mode if self.rag_enabled else RagMode.OFF

    @classmethod
    def load(cls) -> Settings:
        return cls()
