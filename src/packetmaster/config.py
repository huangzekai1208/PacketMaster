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
    LOCAL_RERANK_API_KEY: str | None = None
    LOCAL_JUDGE_API_KEY: str | None = None
    LOCAL_RAG_ENABLED = False
    LOCAL_RAG_MODE = RagMode.SHADOW
    LOCAL_RAG_KEYWORD_TOP_K = 20
    LOCAL_RAG_VECTOR_TOP_K = 20
    LOCAL_RERANKER_ENABLED = True
    LOCAL_RERANKER_CANDIDATE_TOP_K = 20
    LOCAL_RAG_FINAL_TOP_K = 8
else:
    LOCAL_MODEL_API_KEY = _local_config.MODEL_API_KEY
    LOCAL_MODEL_BASE_URL = _local_config.MODEL_BASE_URL
    LOCAL_MODEL_NAME = _local_config.MODEL_NAME
    LOCAL_STRUCTURED_OUTPUT_METHOD = _local_config.MODEL_STRUCTURED_OUTPUT_METHOD
    LOCAL_EMBEDDING_API_KEY = getattr(_local_config, "EMBEDDING_API_KEY", None)
    LOCAL_RERANK_API_KEY = getattr(_local_config, "RERANK_API_KEY", None)
    LOCAL_JUDGE_API_KEY = getattr(_local_config, "JUDGE_API_KEY", None)
    LOCAL_RAG_ENABLED = bool(getattr(_local_config, "RAG_ENABLED", False))
    LOCAL_RAG_MODE = RagMode(getattr(_local_config, "RAG_MODE", RagMode.SHADOW))
    LOCAL_RAG_KEYWORD_TOP_K = int(getattr(_local_config, "RAG_KEYWORD_TOP_K", 20))
    LOCAL_RAG_VECTOR_TOP_K = int(getattr(_local_config, "RAG_VECTOR_TOP_K", 20))
    LOCAL_RERANKER_ENABLED = bool(
        getattr(_local_config, "RERANKER_ENABLED", True)
    )
    LOCAL_RERANKER_CANDIDATE_TOP_K = int(
        getattr(_local_config, "RERANKER_CANDIDATE_TOP_K", 20)
    )
    LOCAL_RAG_FINAL_TOP_K = int(getattr(_local_config, "RAG_FINAL_TOP_K", 8))


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
    model_input_cost_per_million_usd: float | None = Field(default=None, ge=0)
    model_output_cost_per_million_usd: float | None = Field(default=None, ge=0)
    llm_observability_enabled: bool = True
    evidence_timeout_seconds: int = Field(default=120, gt=0, le=600)
    speed_analyzer_mode: str = "real"
    speed_analyzer_script: Path | None = None
    artifact_root: Path = Path("artifacts")
    artifact_ttl_hours: int = Field(default=24, gt=0)
    tshark_path: str = "tshark"
    max_inspection_rounds: int = Field(default=3, ge=1, le=3)
    # Web 仅绑定 loopback。上传报文会被复制至 artifact_root/web-captures。
    web_database_path: Path = Path("artifacts/packetmaster-web.sqlite")
    web_allowed_capture_roots: list[Path] = Field(default_factory=lambda: [Path.cwd()])
    web_host: Literal["127.0.0.1"] = "127.0.0.1"
    web_port: int = Field(default=8765, ge=1024, le=65535)
    # RAG 默认关闭；active 模式还必须通过持久化的正式评估门禁。
    rag_enabled: bool = LOCAL_RAG_ENABLED
    rag_mode: RagMode = LOCAL_RAG_MODE
    knowledge_database_path: Path = Field(
        default=Path("artifacts/knowledge/packetmaster-knowledge.sqlite"),
        exclude=True,
        repr=False,
    )
    # 默认使用 DashScope 原生多模态向量模型；文本知识也通过同一模型索引。
    embedding_provider: Literal["dashscope"] = "dashscope"
    embedding_model: str = Field(
        default="qwen3-vl-embedding", min_length=1, max_length=256
    )
    embedding_dimension: int = Field(default=2560, ge=1, le=4096)
    embedding_api_key: SecretStr | None = Field(
        default=(
            SecretStr(LOCAL_EMBEDDING_API_KEY) if LOCAL_EMBEDDING_API_KEY else None
        ),
        exclude=True,
        repr=False,
    )
    # DashScope OpenAI 兼容地址，供 text-embedding-v4 等文本模型使用。
    embedding_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-mode/v1",
        min_length=1,
    )
    # qwen3-vl-embedding 使用 DashScope 原生多模态 Embedding 端点。
    embedding_multimodal_base_url: str = Field(
        default=(
            "https://dashscope.aliyuncs.com/api/v1/services/embeddings/"
            "multimodal-embedding/multimodal-embedding"
        ),
        min_length=1,
    )
    embedding_timeout_seconds: float = Field(default=15, gt=0, le=60)
    embedding_max_retries: int = Field(default=2, ge=0, le=5)
    reranker_enabled: bool = LOCAL_RERANKER_ENABLED
    reranker_model: str = Field(default="qwen3-rerank", min_length=1, max_length=256)
    reranker_api_key: SecretStr | None = Field(
        default=(SecretStr(LOCAL_RERANK_API_KEY) if LOCAL_RERANK_API_KEY else None),
        exclude=True,
        repr=False,
    )
    reranker_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-api/v1",
        min_length=1,
    )
    reranker_candidate_top_k: int = Field(
        default=LOCAL_RERANKER_CANDIDATE_TOP_K, ge=1, le=100
    )
    reranker_timeout_seconds: float = Field(default=1.5, gt=0, le=30)
    reranker_max_retries: int = Field(default=0, ge=0, le=3)
    reranker_max_document_chars: int = Field(default=3_500, ge=256, le=12_000)
    judge_enabled: bool = False
    judge_model: str = Field(default="qwen-plus", min_length=1, max_length=256)
    judge_model_revision: str | None = Field(default=None, max_length=256)
    judge_api_key: SecretStr | None = Field(
        default=(SecretStr(LOCAL_JUDGE_API_KEY) if LOCAL_JUDGE_API_KEY else None),
        exclude=True,
        repr=False,
    )
    judge_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-mode/v1",
        min_length=1,
    )
    judge_timeout_seconds: float = Field(default=30, gt=0, le=120)
    judge_max_retries: int = Field(default=1, ge=0, le=3)
    judge_temperature: float = Field(default=0, ge=0, le=0)
    judge_max_tokens: int = Field(default=2_000, ge=256, le=8_000)
    rag_keyword_top_k: int = Field(default=LOCAL_RAG_KEYWORD_TOP_K, ge=1, le=100)
    rag_vector_top_k: int = Field(default=LOCAL_RAG_VECTOR_TOP_K, ge=1, le=100)
    rag_vector_timeout_seconds: float = Field(default=1.25, gt=0, le=30)
    rag_final_top_k: int = Field(default=LOCAL_RAG_FINAL_TOP_K, ge=1, le=8)
    rag_max_context_bytes: int = Field(default=24_576, ge=1_024, le=24_576)
    rag_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
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

    @property
    def effective_reranker_api_key(self) -> SecretStr | None:
        return self.reranker_api_key or self.embedding_api_key

    @classmethod
    def load(cls) -> Settings:
        return cls()
