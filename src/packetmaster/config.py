"""Runtime settings loaded from environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration whose fields map directly to uppercase environment variables."""

    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    model_base_url: str | None = None
    model_api_key: SecretStr | None = Field(default=None, repr=False)
    model_name: str = "gpt-4.1-mini"
    model_timeout_seconds: int = Field(default=120, gt=0)
    evidence_timeout_seconds: int = Field(default=120, gt=0, le=600)
    speed_analyzer_mode: str = "real"
    speed_analyzer_script: Path | None = None
    artifact_root: Path = Path("artifacts")
    artifact_ttl_hours: int = Field(default=24, gt=0)
    tshark_path: str = "tshark"
    max_inspection_rounds: int = Field(default=3, ge=1, le=3)

    @classmethod
    def load(cls) -> Settings:
        return cls()
