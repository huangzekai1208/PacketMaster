"""从本地默认值与环境变量加载的运行时配置。"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from packetmaster.rag.contracts import RagMode

try:
    # config_local.py 被 Git 忽略，适合保存开发机的非共享默认值。
    from packetmaster import config_local as _local_config
except ModuleNotFoundError as exc:
    if exc.name != "packetmaster.config_local":
        raise
    LOCAL_MODEL_API_KEY: str | None = None
    LOCAL_MODEL_BASE_URL: str | None = None
    LOCAL_MODEL_NAME = "gpt-4.1-mini"
    LOCAL_STRUCTURED_OUTPUT_METHOD = "auto"
    LOCAL_EMBEDDING_API_KEY: str | None = None
else:
    LOCAL_MODEL_API_KEY = _local_config.MODEL_API_KEY
    LOCAL_MODEL_BASE_URL = _local_config.MODEL_BASE_URL
    LOCAL_MODEL_NAME = _local_config.MODEL_NAME
    LOCAL_STRUCTURED_OUTPUT_METHOD = _local_config.MODEL_STRUCTURED_OUTPUT_METHOD
    LOCAL_EMBEDDING_API_KEY = getattr(_local_config, "EMBEDDING_API_KEY", None)


class Settings(BaseSettings):
    """运行时配置：本地默认值可被同名大写环境变量覆盖。"""

    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    # 主诊断模型使用 OpenAI 兼容接口；SecretStr 防止密钥出现在 repr 或日志中。
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
    # Web 仅绑定 loopback。上传报文会被复制至 artifact_root/web-captures。
    web_database_path: Path = Path("artifacts/packetmaster-web.sqlite")
    web_allowed_capture_roots: list[Path] = Field(
        default_factory=lambda: [Path.cwd()]
    )
    web_host: Literal["127.0.0.1"] = "127.0.0.1"
    web_port: int = Field(default=8765, ge=1024, le=65535)
    # RAG 默认关闭；active 模式还必须通过持久化的正式评估门禁。
    rag_enabled: bool = False
    rag_mode: RagMode = RagMode.SHADOW
    knowledge_database_path: Path = Field(
        default=Path("artifacts/knowledge/packetmaster-knowledge.sqlite"),
        exclude=True,
        repr=False,
    )
    # 当前只支持 DashScope text-embedding-v4，避免本地模型与索引维度不一致。
    embedding_provider: Literal["dashscope"] = "dashscope"
    embedding_model: str = Field(
        default="text-embedding-v4", min_length=1, max_length=256
    )
    embedding_dimension: int = Field(default=1024, ge=1, le=4096)
    embedding_api_key: SecretStr | None = Field(
        default=(
            SecretStr(LOCAL_EMBEDDING_API_KEY) if LOCAL_EMBEDDING_API_KEY else None
        ),
        exclude=True,
        repr=False,
    )
    # DashScope 的 OpenAI 兼容地址；通常不需要修改，私有网关时才覆盖。
    embedding_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-mode/v1",
        min_length=1,
    )
    embedding_timeout_seconds: float = Field(default=15, gt=0, le=60)
    embedding_max_retries: int = Field(default=2, ge=0, le=5)
    rag_keyword_top_k: int = Field(default=20, ge=1, le=100)
    rag_vector_top_k: int = Field(default=20, ge=1, le=100)
    rag_final_top_k: int = Field(default=8, ge=1, le=8)
    rag_max_context_bytes: int = Field(default=24_576, ge=1_024, le=24_576)
    rag_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    rag_max_chunks: int = Field(default=25_000, ge=1, le=25_000)

    @property
    def effective_rag_mode(self) -> RagMode:
        return self.rag_mode if self.rag_enabled else RagMode.OFF

    @property
    def effective_embedding_model(self) -> str:
        return self.embedding_model

    @property
    def effective_embedding_dimension(self) -> int:
        return self.embedding_dimension

    @classmethod
    def load(cls) -> Settings:
        return cls()
