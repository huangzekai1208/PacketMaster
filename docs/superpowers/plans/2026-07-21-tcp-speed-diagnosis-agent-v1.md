# TCP 测速诊断 Agent 第一版实施计划

> **面向执行智能体：** 必须使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans，逐任务实施本计划。所有步骤使用复选框（`- [ ]`）跟踪。

**目标：** 构建一个基于 CLI 的 TCP 测速诊断 Agent，通过 FastMCP 调用真实 speed-analyze 流水线，对完整报文执行聚合并建立本地证据索引，在 LangGraph 中运行有界的证据驱动 ReAct 工作流，最终生成可追溯的结构化报告。

**架构：** 保留现有 speed-analyze 脚本作为报文处理边界，并增强跨平台 TShark 发现、全量流式聚合、多流分析与 SQLite 证据存储能力。本地 FastMCP Server 暴露分析工具和证据工具；LangGraph 状态机负责校验输入、获取全量摘要、生成开放式假设、定向查询证据、复核结论并生成最终报告。

**技术栈：** Python 3.11-3.13、Pydantic 2、FastMCP 2、LangGraph 1、langchain-openai 1、Typer、SQLite、Scapy、TShark、pytest、pytest-asyncio、Ruff。

## 全局约束

- 默认运行路径使用真实 speed-analyze Adapter；Mock Adapter 仅用于测试和演示。
- 原始 pcap/pcapng 字节及完整逐包数据不得进入模型上下文。
- 基础统计必须覆盖所有已识别的测速报文，不允许只分析前 N 个报文。
- 报文文件始终保留在本地，跨进程只传递经过校验的绝对路径。
- 证据响应必须分页，并包含数据来源、覆盖范围和截断信息。
- 候选原因使用自由文本，不采用封闭枚举。
- 常见 TCP 原因只是基础检查清单，不是原因白名单。
- 新假设必须包含支持证据、反向证据、缺失证据和可观测性。
- 证据驱动的 ReAct 循环最多执行三轮取证。
- 当证据无法支持任何原因时，报告返回 `unresolved`，不得强行诊断。
- RAG、Web UI、批量调度、监控集成和多 Agent 编排不属于第一版范围。
- 保留所有无关的用户修改，包括当前已修改的 `.DS_Store`。

---

## 文件结构

### 项目包

- 创建 `pyproject.toml` —— 包元数据、依赖、CLI 入口、pytest 与 Ruff 配置。
- 创建 `src/speed_agent/__init__.py` —— 包版本。
- 创建 `src/speed_agent/config.py` —— 基于环境变量的运行配置。
- 创建 `src/speed_agent/domain.py` —— 共享 Pydantic 模型与枚举。
- 创建 `src/speed_agent/errors.py` —— 类型化应用错误。
- 创建 `src/speed_agent/artifacts.py` —— 分析目录、保留策略、资源预检和轨迹写入。
- 创建 `src/speed_agent/analyzer/base.py` —— Adapter 协议。
- 创建 `src/speed_agent/analyzer/mock.py` —— 确定性的测试 Adapter。
- 创建 `src/speed_agent/analyzer/real.py` —— 与 speed-analyze 的子进程集成。
- 创建 `src/speed_agent/mcp/server.py` —— FastMCP 工具。
- 创建 `src/speed_agent/mcp/client.py` —— 基于 stdio 的 FastMCP Client 封装。
- 创建 `src/speed_agent/context.py` —— 模型上下文构建器。
- 创建 `src/speed_agent/model.py` —— OpenAI 兼容的结构化输出模型封装。
- 创建 `src/speed_agent/graph.py` —— LangGraph 节点和条件边。
- 创建 `src/speed_agent/report.py` —— 报告渲染与持久化。
- 创建 `src/speed_agent/cli.py` —— Typer CLI。
- 创建 `src/speed_agent/prompts/hypothesis.md` —— 开放式假设 Prompt。
- 创建 `src/speed_agent/prompts/verification.md` —— 证据复核 Prompt。

### speed-analyze 加固

- 创建 `speed-analyze/scripts/lib/__init__.py`。
- 创建 `speed-analyze/scripts/lib/tshark.py` —— 二进制发现、pcap 规范化和流式字段提取。
- 创建 `speed-analyze/scripts/lib/store.py` —— SQLite Schema 和证据查询。
- 创建 `speed-analyze/scripts/lib/aggregate.py` —— 全量 TCP 聚合。
- 创建 `speed-analyze/scripts/lib/progress.py` —— JSONL 进度事件。
- 修改 `speed-analyze/scripts/speed_filter_strip.py` —— 增加进度上报、文件指纹和任务独立输出路径。
- 修改 `speed-analyze/scripts/tcp_extract.py` —— 移除前 5000 包限制、流式读取、聚合所有流并写入 SQLite 证据。
- 修改 `speed-analyze/scripts/run_pipeline.py` —— 增加任务级 CLI、pcap 规范化、全流分析和结构化清单。
- 修改 `speed-analyze/SKILL.md` —— 记录新的流水线参数和输出。

### 测试与夹具

- 创建 `tests/conftest.py`。
- 创建 `tests/__init__.py`。
- 创建 `tests/helpers.py`。
- 创建 `tests/fakes.py`。
- 创建 `tests/unit/test_domain.py`。
- 创建 `tests/unit/test_artifacts.py`。
- 创建 `tests/unit/test_tshark.py`。
- 创建 `tests/unit/test_aggregate.py`。
- 创建 `tests/unit/test_store.py`。
- 创建 `tests/unit/test_context.py`。
- 创建 `tests/unit/test_graph.py`。
- 创建 `tests/contract/test_mcp_tools.py`。
- 创建 `tests/integration/test_real_pipeline.py`。
- 创建 `tests/integration/test_cli.py`。
- 创建 `tests/performance/test_large_capture.py`。
- 创建 `tests/fixtures/mock_analysis.json`。
- 创建 `tests/fixtures/packet_rows.jsonl`。
- 创建 `scripts/generate_test_capture.py`。
- 创建 `README.md`。

---

### 任务 1：初始化 Python 项目和共享领域契约

**文件：**
- 创建：`pyproject.toml`
- 创建：`src/speed_agent/__init__.py`
- 创建：`src/speed_agent/config.py`
- 创建：`src/speed_agent/domain.py`
- 创建：`src/speed_agent/errors.py`
- 创建：`tests/unit/test_domain.py`

**接口：**
- 产出：`Settings.load() -> Settings`
- 产出：`AnalyzeRequest`、`AnalyzeResponse`、`EvidenceRequest`、`EvidenceResponse`
- 产出：`Hypothesis`、`HypothesisBatch`、`VerificationResult`、`DiagnosticReport`
- 产出：`AppError(code, message, recoverable, suggested_action, details)`

- [ ] **步骤 1：编写失败的领域模型测试**

```python
from pydantic import ValidationError
import pytest

from speed_agent.domain import (
    AnalyzeRequest,
    EvidencePredicate,
    Hypothesis,
    HypothesisType,
    Observability,
)


def test_hypothesis_cause_is_open_text() -> None:
    item = Hypothesis(
        cause="测速服务端线程调度呈周期性停顿",
        hypothesis_type=HypothesisType.DATA_DISCOVERED,
        observability=Observability.INDIRECT,
        confidence="medium",
        supporting_evidence=[],
        contradicting_evidence=[],
        missing_evidence=["server CPU profile"],
        affected_flows=["flow-3"],
        explanation="吞吐周期下降但 TCP 丢包指标正常",
        suggestion="采集服务端 CPU 和应用发送速率",
    )
    assert item.cause == "测速服务端线程调度呈周期性停顿"


def test_analyze_request_rejects_relative_path(tmp_path) -> None:
    with pytest.raises(ValidationError):
        AnalyzeRequest(
            request_id="analysis-1",
            pcap_path="capture.pcapng",
            target="download",
        )


def test_evidence_predicate_rejects_unknown_operator() -> None:
    with pytest.raises(ValidationError):
        EvidencePredicate(field="tcp.seq", operator="shell", value="x")
```

- [ ] **步骤 2：运行测试并确认失败**

运行：

```bash
python3 -m pytest tests/unit/test_domain.py -v
```

预期：由于 `speed_agent` 尚不存在，测试收集失败。

- [ ] **步骤 3：创建包元数据**

在 `pyproject.toml` 中使用以下依赖：

```toml
[project]
name = "tcp-speed-diagnosis-agent"
version = "0.1.0"
requires-python = ">=3.11,<3.14"
dependencies = [
  "fastmcp>=2.12,<3",
  "langgraph>=1.0,<2",
  "langchain-openai>=1.0,<2",
  "pydantic>=2.8,<3",
  "pydantic-settings>=2.4,<3",
  "typer>=0.16,<1",
  "scapy>=2.5,<3",
  "psutil>=6,<8",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.3,<9",
  "pytest-asyncio>=0.25,<2",
  "ruff>=0.9,<1",
]

[project.scripts]
speed-agent = "speed_agent.cli:app"

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
  "integration: requires local packet-analysis dependencies",
  "performance: requires an external large capture",
]

[tool.ruff]
line-length = 100
target-version = "py311"
```

- [ ] **步骤 4：实现共享模型**

在 `src/speed_agent/domain.py` 中定义精确枚举值，并允许原因使用自由文本：

```python
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Target(StrEnum):
    DOWNLOAD = "download"
    UPLOAD = "upload"
    BOTH = "both"


class HypothesisType(StrEnum):
    KNOWN_PATTERN = "known_pattern"
    DATA_DISCOVERED = "data_discovered"
    EXTERNAL_FACTOR = "external_factor"


class Observability(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    OUTSIDE_CAPTURE = "outside_capture"


class CoverageSummary(BaseModel):
    input_size_bytes: int = Field(ge=0)
    total_packets_seen: int = Field(ge=0)
    tcp_packets_seen: int = Field(ge=0)
    speed_packets_analyzed: int = Field(ge=0)
    analyzed_bytes: int = Field(ge=0)
    analyzed_duration_seconds: float = Field(ge=0)
    complete: bool
    truncated: bool
    truncation_reason: str | None = None


class AnalyzeRequest(BaseModel):
    request_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9._-]+$")
    pcap_path: Path
    target: Target
    aggregation_interval_seconds: int = Field(default=1, ge=1, le=60)
    build_evidence_index: bool = True

    @field_validator("pcap_path")
    @classmethod
    def require_absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("pcap_path must be absolute")
        return value


class AnalyzeResponse(BaseModel):
    analysis_id: str
    status: Literal["completed", "partial", "failed"]
    coverage_summary: CoverageSummary
    flow_summary: dict[str, Any]
    tcp_summary: dict[str, Any]
    interval_summary: list[dict[str, Any]]
    syn_options: dict[str, Any]
    available_evidence: list[str]
    resource_usage: dict[str, Any]
    warnings: list[str]
    artifact_paths: dict[str, str]


class EvidencePredicate(BaseModel):
    field: str
    operator: Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "exists"]
    value: Any = None


class CustomEvidenceQuery(BaseModel):
    flow_ids: list[str] = []
    time_start: float | None = Field(default=None, ge=0)
    time_end: float | None = Field(default=None, ge=0)
    predicates: list[EvidencePredicate] = []
    fields: list[str] = []


class EvidenceRequest(BaseModel):
    analysis_id: str
    evidence_type: str
    flow_id: str | None = None
    time_start: float | None = Field(default=None, ge=0)
    time_end: float | None = Field(default=None, ge=0)
    fields: list[str] = []
    query: CustomEvidenceQuery | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


class EvidenceResponse(BaseModel):
    analysis_id: str
    evidence_type: str
    summary: dict[str, Any]
    items: list[dict[str, Any]]
    total: int = Field(ge=0)
    next_offset: int | None
    truncated: bool
    source: str
    coverage_range: dict[str, Any]
    warnings: list[str]


class Hypothesis(BaseModel):
    cause: str = Field(min_length=1)
    hypothesis_type: HypothesisType
    observability: Observability
    confidence: Literal["low", "medium", "high"]
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    missing_evidence: list[str]
    affected_flows: list[str]
    explanation: str
    suggestion: str


class HypothesisBatch(BaseModel):
    hypotheses: list[Hypothesis]
    requested_evidence: list[EvidenceRequest]


class VerificationResult(BaseModel):
    accepted_hypotheses: list[Hypothesis]
    rejected_causes: list[str]
    requested_evidence: list[EvidenceRequest]
    ready_for_report: bool
    confidence: Literal["low", "medium", "high"]
    limitations: list[str]


class DiagnosticReport(BaseModel):
    standard_bandwidth_mbps: float = Field(gt=0)
    actual_bandwidth_mbps: float = Field(gt=0)
    achievement_ratio_pct: float = Field(ge=0)
    target: Target
    primary_cause: str
    candidate_causes: list[Hypothesis]
    key_evidence: list[dict[str, Any]]
    confidence: Literal["low", "medium", "high"]
    coverage_summary: CoverageSummary
    evidence_quality: dict[str, Any]
    limitations: list[str]
    troubleshooting_steps: list[str]
    optimization_suggestions: list[str]
    analysis_metadata: dict[str, Any]
```

- [ ] **步骤 5：实现配置和错误类型**

```python
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    model_base_url: str
    model_api_key: str
    model_name: str
    model_timeout_seconds: float = Field(default=60, gt=0)
    speed_analyzer_mode: str = "real"
    artifact_root: str = "output"
    artifact_ttl_hours: int = Field(default=24, ge=1)
    tshark_path: str | None = None
    max_inspection_rounds: int = Field(default=3, ge=1, le=3)

    @classmethod
    def load(cls) -> "Settings":
        return cls()
```

`src/speed_agent/errors.py`:

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AppError(Exception):
    code: str
    message: str
    recoverable: bool
    suggested_action: str
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
```

- [ ] **步骤 6：运行单元测试和静态检查**

运行：

```bash
python3 -m pytest tests/unit/test_domain.py -v
python3 -m ruff check src/speed_agent tests/unit/test_domain.py
```

预期：所有领域模型测试通过，Ruff 退出码为 0。

- [ ] **步骤 7：提交**

```bash
git add pyproject.toml src/speed_agent tests/unit/test_domain.py
git commit -m "feat: add agent package and domain contracts"
```

---

### 任务 2：增加产物管理和资源预检

**文件：**
- 创建：`src/speed_agent/artifacts.py`
- 创建：`tests/unit/test_artifacts.py`

**接口：**
- 消费：`Settings` 和 `AppError`
- 产出：`ArtifactPaths`
- 产出：`ArtifactManager.create(request_id) -> ArtifactPaths`
- 产出：`ArtifactManager.preflight(input_path, target) -> ResourceBudget`
- 产出：`ArtifactManager.append_trace(paths: ArtifactPaths, event: dict[str, Any]) -> None`
- 产出：`ArtifactManager.mark_keep(paths: ArtifactPaths) -> None`
- 产出：`ArtifactManager.cleanup_expired(now: datetime) -> list[Path]`
- 产出：`create_request_id() -> str`

- [ ] **步骤 1：编写失败测试**

```python
from datetime import datetime, timezone
import os
from pathlib import Path

import pytest

from speed_agent.artifacts import ArtifactManager
from speed_agent.errors import AppError


def test_create_uses_isolated_analysis_directory(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=24)
    paths = manager.create("analysis-1")
    assert paths.root == tmp_path / "analysis-1"
    assert paths.filtered_dir.is_dir()
    assert paths.logs_dir.is_dir()


def test_preflight_rejects_insufficient_disk(monkeypatch, tmp_path: Path) -> None:
    capture = tmp_path / "large.pcapng"
    capture.write_bytes(b"x" * 100)
    manager = ArtifactManager(tmp_path / "out", ttl_hours=24)
    monkeypatch.setattr(manager, "_free_bytes", lambda _: 10)
    with pytest.raises(AppError, match="INSUFFICIENT_DISK_SPACE"):
        manager.preflight(capture, "download")


def test_cleanup_preserves_keep_marker(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=1)
    kept = manager.create("kept")
    expired = manager.create("expired")
    manager.mark_keep(kept)
    old = datetime.now(timezone.utc).timestamp() - 7200
    os.utime(kept.root, (old, old))
    os.utime(expired.root, (old, old))
    removed = manager.cleanup_expired(datetime.now(timezone.utc))
    assert expired.root in removed
    assert kept.root.exists()
```

- [ ] **步骤 2：确认测试失败**

运行：

```bash
python3 -m pytest tests/unit/test_artifacts.py -v
```

预期：导入 `speed_agent.artifacts` 失败。

- [ ] **步骤 3：实现产物管理和资源预检**

使用不可变路径，并采用输入文件大小 1.5 倍的安全系数：

```python
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import shutil
from typing import Any

from speed_agent.errors import AppError


@dataclass(frozen=True, slots=True)
class ArtifactPaths:
    root: Path
    filtered_dir: Path
    logs_dir: Path
    coverage_json: Path
    speed_stats_json: Path
    tcp_analysis_json: Path
    analysis_db: Path
    report_json: Path
    trace_jsonl: Path


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    input_size_bytes: int
    required_free_bytes: int
    available_free_bytes: int


class ArtifactManager:
    def __init__(self, root: Path, ttl_hours: int) -> None:
        self.root = root.resolve()
        self.ttl_hours = ttl_hours

    def create(self, request_id: str) -> ArtifactPaths:
        root = self.root / request_id
        filtered = root / "filtered"
        logs = root / "logs"
        filtered.mkdir(parents=True, exist_ok=True)
        logs.mkdir(parents=True, exist_ok=True)
        return ArtifactPaths(
            root=root,
            filtered_dir=filtered,
            logs_dir=logs,
            coverage_json=root / "coverage.json",
            speed_stats_json=root / "speed_stats.json",
            tcp_analysis_json=root / "tcp_analysis.json",
            analysis_db=root / "analysis.sqlite",
            report_json=root / "report.json",
            trace_jsonl=root / "trace.jsonl",
        )

    def _free_bytes(self, path: Path) -> int:
        return shutil.disk_usage(path).free

    def preflight(self, input_path: Path, target: str) -> ResourceBudget:
        size = input_path.stat().st_size
        fixed_margin = 1024**3
        required = int(size * 1.5) + fixed_margin
        self.root.mkdir(parents=True, exist_ok=True)
        available = self._free_bytes(self.root)
        if available < required:
            raise AppError(
                code="INSUFFICIENT_DISK_SPACE",
                message=f"INSUFFICIENT_DISK_SPACE: need {required} bytes",
                recoverable=True,
                suggested_action="Free disk space or choose another artifact root",
                details={"required": required, "available": available, "target": target},
            )
        return ResourceBudget(size, required, available)

    def append_trace(self, paths: ArtifactPaths, event: dict[str, Any]) -> None:
        with paths.trace_jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    def mark_keep(self, paths: ArtifactPaths) -> None:
        (paths.root / ".keep").touch()

    def cleanup_expired(self, now: datetime) -> list[Path]:
        removed: list[Path] = []
        cutoff = now.timestamp() - self.ttl_hours * 3600
        if not self.root.exists():
            return removed
        for child in self.root.iterdir():
            if not child.is_dir() or (child / ".keep").exists():
                continue
            if child.stat().st_mtime < cutoff:
                shutil.rmtree(child)
                removed.append(child)
        return removed


def create_request_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{secrets.token_hex(4)}"
```

- [ ] **步骤 4：运行测试**

```bash
python3 -m pytest tests/unit/test_artifacts.py -v
```

预期：所有测试通过。

- [ ] **步骤 5：提交**

```bash
git add src/speed_agent/artifacts.py tests/unit/test_artifacts.py
git commit -m "feat: add artifact and resource management"
```

---

### 任务 3：增加跨平台 TShark 发现和流式提取

**文件：**
- 创建：`speed-analyze/scripts/lib/__init__.py`
- 创建：`speed-analyze/scripts/lib/tshark.py`
- 创建：`speed-analyze/scripts/lib/progress.py`
- 创建：`tests/unit/test_tshark.py`
- 创建：`tests/__init__.py`
- 创建：`tests/helpers.py`

**接口：**
- 产出：`find_tshark(configured: str | None) -> Path`
- 产出：`normalize_capture(input_path, output_dir, tshark_path) -> Path`
- 产出：`stream_tshark_fields(tshark_path, capture, fields, display_filter) -> Iterator[dict[str, str]]`
- 产出：`ProgressWriter.emit(stage, current, total, message)`

- [ ] **步骤 1：编写失败测试**

```python
from pathlib import Path

import pytest

from tests.helpers import load_script_module


tshark = load_script_module("lib/tshark.py", "speed_tshark")


def test_find_tshark_prefers_configured_path(tmp_path: Path) -> None:
    binary = tmp_path / "tshark"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    assert tshark.find_tshark(str(binary)) == binary


def test_stream_tshark_fields_reads_every_row(monkeypatch, tmp_path: Path) -> None:
    rows = ["0.1\t1\n", "0.2\t2\n", "9.9\t9999\n"]

    class FakeStream:
        def __init__(self, values: list[str]) -> None:
            self._values = iter(values)

        def __iter__(self):
            return self

        def __next__(self) -> str:
            return next(self._values)

        def read(self) -> str:
            return ""

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = FakeStream(rows)
            self.stderr = FakeStream([])

        def wait(self) -> int:
            return 0

    fake = FakeProcess()
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *a, **k: fake)
    result = list(
        tshark.stream_tshark_fields(
            Path("/usr/bin/tshark"),
            tmp_path / "x.pcapng",
            ["frame.time_relative", "frame.number"],
            "tcp",
        )
    )
    assert result[-1]["frame.number"] == "9999"
    assert len(result) == 3
```

创建 `tests/helpers.py`，内容如下：

```python
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import ModuleType


SCRIPT_ROOT = Path(__file__).resolve().parents[1] / "speed-analyze" / "scripts"


def load_script_module(relative_path: str, module_name: str) -> ModuleType:
    if str(SCRIPT_ROOT) not in sys.path:
        sys.path.insert(0, str(SCRIPT_ROOT))
    path = SCRIPT_ROOT / relative_path
    spec = spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module from {path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
```

创建空的 `tests/__init__.py`，共享报文夹具放在 `tests/conftest.py`。

- [ ] **步骤 2：确认测试失败**

```bash
python3 -m pytest tests/unit/test_tshark.py -v
```

预期：模块文件不存在。

- [ ] **步骤 3：实现二进制发现和报文格式规范化**

```python
def find_tshark(configured: str | None = None) -> Path:
    candidates = [
        configured,
        shutil.which("tshark"),
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise RuntimeError("DEPENDENCY_UNAVAILABLE: tshark not found")


def normalize_capture(input_path: Path, output_dir: Path, tshark_path: Path) -> Path:
    if input_path.suffix.lower() == ".pcapng":
        return input_path
    output = output_dir / f"{input_path.stem}.pcapng"
    result = subprocess.run(
        [str(tshark_path), "-r", str(input_path), "-w", str(output)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"INVALID_CAPTURE: {result.stderr[:500]}")
    return output
```

- [ ] **步骤 4：实现无报文数量上限的流式读取**

```python
def stream_tshark_fields(
    tshark_path: Path,
    capture: Path,
    fields: list[str],
    display_filter: str,
) -> Iterator[dict[str, str]]:
    command = [str(tshark_path), "-r", str(capture), "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])
    command.extend(["-Y", display_filter])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        values = line.rstrip("\n").split("\t")
        values.extend([""] * (len(fields) - len(values)))
        yield dict(zip(fields, values, strict=False))
    stderr = process.stderr.read() if process.stderr else ""
    returncode = process.wait()
    if returncode != 0:
        raise RuntimeError(f"ANALYSIS_FAILED: {stderr[:500]}")
```

该命令不得加入 `-c` 参数。

- [ ] **步骤 5：实现 JSONL 进度输出**

```python
class ProgressWriter:
    def __init__(self, path: Path) -> None:
        self.path = path

    def emit(
        self,
        stage: str,
        current: int | None,
        total: int | None,
        message: str,
    ) -> None:
        payload = {
            "stage": stage,
            "current": current,
            "total": total,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
```

- [ ] **步骤 6：运行测试**

```bash
python3 -m pytest tests/unit/test_tshark.py -v
```

预期：二进制发现和全量流式读取测试通过。

- [ ] **步骤 7：提交**

```bash
git add speed-analyze/scripts/lib tests/__init__.py tests/helpers.py tests/conftest.py tests/unit/test_tshark.py
git commit -m "feat: add cross-platform streaming tshark utilities"
```

---

### 任务 4：构建全量报文聚合器和 SQLite 证据库

**文件：**
- 创建：`speed-analyze/scripts/lib/aggregate.py`
- 创建：`speed-analyze/scripts/lib/store.py`
- 创建：`tests/fixtures/packet_rows.jsonl`
- 创建：`tests/unit/test_aggregate.py`
- 创建：`tests/unit/test_store.py`

**接口：**
- 产出：`TcpAccumulator.observe(row) -> None`
- 产出：`TcpAccumulator.finalize() -> AggregationResult`
- 产出：`AnalysisStore.initialize() -> None`
- 产出：`AnalysisStore.write_result(result) -> None`
- 产出：`AnalysisStore.append_event(event) -> None`
- 产出：`AnalysisStore.flush_events() -> None`
- 产出：`AnalysisStore.query_custom(fields, predicates, offset, limit) -> list[dict[str, object]]`

- [ ] **步骤 1：编写回归测试，证明后段异常不会遗漏**

```python
def packet_row(
    frame_number: int,
    time_relative: float,
    retransmission: bool,
) -> dict[str, str]:
    return {
        "frame.number": str(frame_number),
        "frame.time_relative": str(time_relative),
        "ip.src": "192.0.2.10",
        "ip.dst": "192.0.2.20",
        "tcp.srcport": "50000",
        "tcp.dstport": "443",
        "tcp.len": "1460",
        "tcp.analysis.retransmission": "1" if retransmission else "",
    }


def test_accumulator_includes_anomaly_after_packet_5000() -> None:
    accumulator = TcpAccumulator(interval_seconds=1)
    for index in range(6000):
        accumulator.observe(
            packet_row(
                frame_number=index + 1,
                time_relative=index / 1000,
                retransmission=index == 5500,
            )
        )
    result = accumulator.finalize()
    assert result.coverage.total_packets_seen == 6000
    assert result.tcp_summary["retransmission_count"] == 1
    assert result.events[0]["frame_number"] == 5501


def test_event_sink_prevents_anomaly_rows_from_accumulating_in_memory() -> None:
    written = 0

    def sink(event: dict[str, object]) -> None:
        nonlocal written
        written += 1

    accumulator = TcpAccumulator(interval_seconds=1, event_sink=sink)
    for index in range(10_000):
        accumulator.observe(
            packet_row(
                frame_number=index + 1,
                time_relative=index / 1000,
                retransmission=True,
            )
        )
    result = accumulator.finalize()
    assert written == 10_000
    assert result.events == []
```

- [ ] **步骤 2：编写证据库安全测试**

```python
@pytest.fixture
def store(tmp_path: Path) -> AnalysisStore:
    instance = AnalysisStore(tmp_path / "analysis.sqlite")
    instance.initialize()
    return instance


def test_custom_query_rejects_unknown_field(store) -> None:
    with pytest.raises(ValueError, match="field not allowed"):
        store.query_custom(
            fields=["tcp.payload"],
            predicates=[],
            offset=0,
            limit=100,
        )


def test_custom_query_uses_parameterized_values(store, monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(store, "_execute", lambda sql, params: captured.update(sql=sql, params=params) or [])
    store.query_custom(
        fields=["tcp.seq"],
        predicates=[{"field": "tcp.seq", "operator": "eq", "value": "1 OR 1=1"}],
        offset=0,
        limit=100,
    )
    assert "1 OR 1=1" not in captured["sql"]
    assert captured["params"][0] == "1 OR 1=1"
```

- [ ] **步骤 3：确认两个测试文件均失败**

```bash
python3 -m pytest tests/unit/test_aggregate.py tests/unit/test_store.py -v
```

预期：聚合和证据库模块尚不存在。

- [ ] **步骤 4：实现流式聚合器**

维护固定大小的全局计数器、每流计数器、时间区间桶、用于分位数的 RTT 统计、SYN 选项和异常事件。只保存异常报文及必要证据字段。

```python
class TcpAccumulator:
    def __init__(
        self,
        interval_seconds: int,
        event_sink: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.event_sink = event_sink
        self.total_packets = 0
        self.tcp_packets = 0
        self.analyzed_bytes = 0
        self.flows: dict[str, FlowAccumulator] = {}
        self.intervals: dict[int, IntervalAccumulator] = {}
        self.events: list[dict[str, object]] = []

    def observe(self, row: dict[str, str]) -> None:
        self.total_packets += 1
        flow_id = normalized_flow_id(row)
        flow = self.flows.setdefault(flow_id, FlowAccumulator(flow_id))
        interval_id = int(float(row["frame.time_relative"]) // self.interval_seconds)
        interval = self.intervals.setdefault(interval_id, IntervalAccumulator(interval_id))
        payload_bytes = parse_int(row.get("tcp.len"))
        flow.observe(row, payload_bytes)
        interval.observe(row, payload_bytes)
        self.analyzed_bytes += payload_bytes
        for event_type in detect_events(row):
            event = event_record(flow_id, event_type, row)
            if self.event_sink is None:
                self.events.append(event)
            else:
                self.event_sink(event)

    def finalize(self) -> AggregationResult:
        return build_result(
            total_packets=self.total_packets,
            analyzed_bytes=self.analyzed_bytes,
            flows=self.flows,
            intervals=self.intervals,
            events=self.events,
            complete=True,
            truncated=False,
        )
```

在 `aggregate.py` 中定义以下辅助类型和函数：

```python
@dataclass
class FlowAccumulator:
    flow_id: str
    packet_count: int = 0
    payload_bytes: int = 0
    retransmission_count: int = 0

    def observe(self, row: dict[str, str], payload_bytes: int) -> None:
        self.packet_count += 1
        self.payload_bytes += payload_bytes
        if row.get("tcp.analysis.retransmission"):
            self.retransmission_count += 1


@dataclass
class IntervalAccumulator:
    interval_id: int
    packet_count: int = 0
    payload_bytes: int = 0
    retransmission_count: int = 0

    def observe(self, row: dict[str, str], payload_bytes: int) -> None:
        self.packet_count += 1
        self.payload_bytes += payload_bytes
        if row.get("tcp.analysis.retransmission"):
            self.retransmission_count += 1


@dataclass
class AggregationResult:
    coverage: CoverageSummary
    tcp_summary: dict[str, object]
    flows: list[dict[str, object]]
    intervals: list[dict[str, object]]
    events: list[dict[str, object]]
    syn_options: dict[str, object]

    def to_summary_dict(self) -> dict[str, object]:
        return {
            "coverage_summary": self.coverage.model_dump(),
            "tcp_summary": self.tcp_summary,
            "flow_summary": {"flows": self.flows},
            "interval_summary": self.intervals,
            "syn_options": self.syn_options,
        }


def parse_int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def normalized_flow_id(row: dict[str, str]) -> str:
    src = row.get("ip.src") or row.get("ipv6.src") or ""
    dst = row.get("ip.dst") or row.get("ipv6.dst") or ""
    left = (src, parse_int(row.get("tcp.srcport")))
    right = (dst, parse_int(row.get("tcp.dstport")))
    first, second = sorted((left, right))
    return f"{first[0]}:{first[1]}-{second[0]}:{second[1]}"


def detect_events(row: dict[str, str]) -> list[str]:
    mapping = {
        "tcp.analysis.retransmission": "retransmission",
        "tcp.analysis.fast_retransmission": "fast_retransmission",
        "tcp.analysis.duplicate_ack": "duplicate_ack",
        "tcp.analysis.out_of_order": "out_of_order",
        "tcp.analysis.zero_window": "zero_window",
    }
    return [name for field, name in mapping.items() if row.get(field)]


def event_record(
    flow_id: str,
    event_type: str,
    row: dict[str, str],
) -> dict[str, object]:
    return {
        "event_type": event_type,
        "frame_number": parse_int(row.get("frame.number")),
        "time_relative": float(row.get("frame.time_relative") or 0),
        "flow_id": flow_id,
        "fields": {
            "tcp.seq": row.get("tcp.seq", ""),
            "tcp.ack": row.get("tcp.ack", ""),
            "tcp.window_size": row.get("tcp.window_size", ""),
        },
    }
```

在同一模块中实现 `build_result`：

```python
def build_result(
    total_packets: int,
    analyzed_bytes: int,
    flows: dict[str, FlowAccumulator],
    intervals: dict[int, IntervalAccumulator],
    events: list[dict[str, object]],
    complete: bool,
    truncated: bool,
) -> AggregationResult:
    interval_rows = [
        {
            "interval_start": float(key),
            "interval_end": float(key + 1),
            "packet_count": item.packet_count,
            "payload_bytes": item.payload_bytes,
            "throughput_mbps": item.payload_bytes * 8 / 1_000_000,
            "retransmission_count": item.retransmission_count,
        }
        for key, item in sorted(intervals.items())
    ]
    flow_rows = [
        {
            "flow_id": flow_id,
            "packet_count": item.packet_count,
            "payload_bytes": item.payload_bytes,
            "retransmission_count": item.retransmission_count,
        }
        for flow_id, item in sorted(flows.items())
    ]
    duration = interval_rows[-1]["interval_end"] if interval_rows else 0.0
    retransmissions = sum(item.retransmission_count for item in flows.values())
    return AggregationResult(
        coverage=CoverageSummary(
            input_size_bytes=0,
            total_packets_seen=total_packets,
            tcp_packets_seen=total_packets,
            speed_packets_analyzed=total_packets,
            analyzed_bytes=analyzed_bytes,
            analyzed_duration_seconds=duration,
            complete=complete,
            truncated=truncated,
        ),
        tcp_summary={
            "avg_throughput_mbps": (
                analyzed_bytes * 8 / duration / 1_000_000 if duration else 0.0
            ),
            "retransmission_count": retransmissions,
        },
        flows=flow_rows,
        intervals=interval_rows,
        events=events,
        syn_options={},
    )
```

任务 5 在保持返回类型不变的前提下，继续补充 RTT 直方图、窗口统计、SYN 选项、方向字节数和精确输入大小。

使用毫秒桶 `[1, 5, 10, 20, 50, 100, 200, 500, 1000, inf]` 的固定 RTT 直方图，不得在内存中保留全部 RTT 样本。

- [ ] **步骤 5：实现 SQLite Schema**

```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
CREATE TABLE flows (
    flow_id TEXT PRIMARY KEY,
    metrics_json TEXT NOT NULL
);
CREATE TABLE intervals (
    interval_start REAL NOT NULL,
    interval_end REAL NOT NULL,
    flow_id TEXT,
    metrics_json TEXT NOT NULL
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    frame_number INTEGER NOT NULL,
    time_relative REAL NOT NULL,
    flow_id TEXT NOT NULL,
    fields_json TEXT NOT NULL
);
CREATE INDEX idx_events_type_time ON events(event_type, time_relative);
CREATE INDEX idx_events_flow_time ON events(flow_id, time_relative);
```

将允许的 DSL 字段映射为 JSON 提取表达式或显式列。操作符必须来自静态字典，查询值必须作为 SQL 参数传入。

实现证据库 API：

```python
ALLOWED_FIELD_SQL = {
    "frame.number": "frame_number",
    "frame.time_relative": "time_relative",
    "flow_id": "flow_id",
    "event_type": "event_type",
    "tcp.seq": "json_extract(fields_json, '$.\"tcp.seq\"')",
    "tcp.ack": "json_extract(fields_json, '$.\"tcp.ack\"')",
    "tcp.window_size": "json_extract(fields_json, '$.\"tcp.window_size\"')",
}
OPERATOR_SQL = {
    "eq": "=",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}


class AnalysisStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._event_buffer: list[dict[str, object]] = []

    def initialize(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.executescript(SCHEMA_SQL)

    def write_result(self, result: AggregationResult) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value_json) VALUES (?, ?)",
                ("coverage", json.dumps(result.coverage.model_dump())),
            )
            connection.executemany(
                "INSERT OR REPLACE INTO flows(flow_id, metrics_json) VALUES (?, ?)",
                [
                    (str(item["flow_id"]), json.dumps(item))
                    for item in result.flows
                ],
            )
            connection.executemany(
                "INSERT INTO intervals(interval_start, interval_end, flow_id, metrics_json) "
                "VALUES (?, ?, ?, ?)",
                [
                    (
                        float(item["interval_start"]),
                        float(item["interval_end"]),
                        item.get("flow_id"),
                        json.dumps(item),
                    )
                    for item in result.intervals
                ],
            )
            connection.executemany(
                "INSERT INTO events(event_type, frame_number, time_relative, flow_id, fields_json) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        item["event_type"],
                        item["frame_number"],
                        item["time_relative"],
                        item["flow_id"],
                        json.dumps(item["fields"]),
                    )
                    for item in result.events
                ],
            )

    def append_event(self, event: dict[str, object]) -> None:
        self._event_buffer.append(event)
        if len(self._event_buffer) >= 1000:
            self.flush_events()

    def flush_events(self) -> None:
        if not self._event_buffer:
            return
        rows = [
            (
                item["event_type"],
                item["frame_number"],
                item["time_relative"],
                item["flow_id"],
                json.dumps(item["fields"]),
            )
            for item in self._event_buffer
        ]
        with sqlite3.connect(self.path) as connection:
            connection.executemany(
                "INSERT INTO events(event_type, frame_number, time_relative, flow_id, fields_json) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        self._event_buffer.clear()

    def query_custom(
        self,
        fields: list[str],
        predicates: list[dict[str, object]],
        offset: int,
        limit: int,
    ) -> list[dict[str, object]]:
        for field in fields:
            if field not in ALLOWED_FIELD_SQL:
                raise ValueError(f"field not allowed: {field}")
        selected = ", ".join(
            f"{ALLOWED_FIELD_SQL[field]} AS \"{field}\"" for field in fields
        )
        clauses: list[str] = []
        params: list[object] = []
        for predicate in predicates:
            field = str(predicate["field"])
            operator = str(predicate["operator"])
            if field not in ALLOWED_FIELD_SQL:
                raise ValueError(f"field not allowed: {field}")
            expression = ALLOWED_FIELD_SQL[field]
            if operator == "exists":
                clauses.append(f"{expression} IS NOT NULL")
                continue
            if operator == "in":
                values = list(predicate["value"])
                if not values:
                    clauses.append("0=1")
                    continue
                placeholders = ", ".join("?" for _ in values)
                clauses.append(f"{expression} IN ({placeholders})")
                params.extend(values)
                continue
            if operator not in OPERATOR_SQL:
                raise ValueError(f"operator not allowed: {operator}")
            clauses.append(f"{expression} {OPERATOR_SQL[operator]} ?")
            params.append(predicate["value"])
        where = " AND ".join(clauses) if clauses else "1=1"
        sql = f"SELECT {selected} FROM events WHERE {where} LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return self._execute(sql, params)

    def _execute(self, sql: str, params: list[object]) -> list[dict[str, object]]:
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(sql, params).fetchall()]
```

- [ ] **步骤 6：运行聚合与证据库测试**

```bash
python3 -m pytest tests/unit/test_aggregate.py tests/unit/test_store.py -v
```

预期：后段异常、分页、字段白名单和防注入测试全部通过。

- [ ] **步骤 7：提交**

```bash
git add speed-analyze/scripts/lib/aggregate.py speed-analyze/scripts/lib/store.py tests/fixtures/packet_rows.jsonl tests/unit/test_aggregate.py tests/unit/test_store.py
git commit -m "feat: add full-capture aggregation and evidence store"
```

---

### 任务 5：将全量聚合集成到真实 speed-analyze 流水线

**文件：**
- 修改：`speed-analyze/scripts/speed_filter_strip.py`
- 修改：`speed-analyze/scripts/tcp_extract.py`
- 修改：`speed-analyze/scripts/run_pipeline.py`
- 修改：`speed-analyze/SKILL.md`
- 修改：`tests/conftest.py`
- 创建：`tests/integration/test_real_pipeline.py`

**接口：**
- 消费：`find_tshark`、`normalize_capture`、`stream_tshark_fields`、`TcpAccumulator`、`AnalysisStore`
- 产出命令：
  `python run_pipeline.py --input ABSOLUTE_PATH --target download --output ANALYSIS_DIR --analysis-id ID --interval 1 --build-evidence-index`
- 产出：`manifest.json`、`coverage.json`、`speed_stats.json`、`tcp_analysis.json`、`analysis.sqlite`

- [ ] **步骤 1：围绕报文夹具编写失败的集成测试**

```python
from pathlib import Path

import pytest
from scapy.all import IP, Raw, TCP
from scapy.utils import PcapNgWriter


@pytest.fixture
def sample_capture(tmp_path: Path) -> Path:
    path = tmp_path / "sample.pcapng"
    writer = PcapNgWriter(str(path))
    client = "192.0.2.10"
    server = "192.0.2.20"
    writer.write(IP(src=client, dst=server) / TCP(sport=50000, dport=443, flags="S", seq=1))
    writer.write(
        IP(src=server, dst=client)
        / TCP(sport=443, dport=50000, flags="SA", seq=1, ack=2)
    )
    for index in range(100):
        writer.write(
            IP(src=server, dst=client)
            / TCP(
                sport=443,
                dport=50000,
                flags="PA",
                seq=2 + index * 1400,
                ack=2,
            )
            / Raw(load=b"x" * 1400)
        )
    writer.close()
    return path


@pytest.mark.integration
def test_pipeline_analyzes_all_filtered_flows(sample_capture, tmp_path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "speed-analyze/scripts/run_pipeline.py",
            "--input",
            str(sample_capture),
            "--target",
            "download",
            "--output",
            str(tmp_path),
            "--analysis-id",
            "integration-1",
            "--interval",
            "1",
            "--build-evidence-index",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    coverage = json.loads((tmp_path / "coverage.json").read_text())
    assert coverage["complete"] is True
    assert coverage["truncated"] is False
    assert (tmp_path / "analysis.sqlite").exists()
```

仅当 TShark 不可用时跳过该测试，并明确写出原因 `tshark not installed`。

- [ ] **步骤 2：运行测试并确认当前流水线失败**

```bash
python3 -m pytest tests/integration/test_real_pipeline.py -v -m integration
```

预期：由于新的 CLI 参数和输出尚不存在，测试失败。

- [ ] **步骤 3：更新测速流筛选**

增加：

- 与原文件名无关的任务独立输出名称；
- 在第一次全量扫描期间计算 SHA-256；
- 按可配置报文间隔输出进度事件；
- 由 run_pipeline 提供结构化摘要路径；
- 默认不剥离 payload。

第一版保留当前两遍扫描算法。

- [ ] **步骤 4：替换存在报文数量限制的 TCP 提取流程**

在 `tcp_extract.py` 中：

- 移除必填的 `--port` 参数；
- 移除 `--max-packets`；
- 移除所有 TShark `-c` 限制；
- 分析方向筛选报文中的全部 TCP 报文；
- 通过 `TcpAccumulator.observe` 流式处理行；
- 写入聚合 JSON 和 `analysis.sqlite`；
- 包含 `speed_stats.json` 中发现的所有测速流；
- IPv4 字段为空时使用 `ipv6.src` 和 `ipv6.dst`；
- 合并 `speed_stats.json` 中的原始文件计数与筛选报文计数，使 `coverage.json` 能区分总报文、TCP 报文和已分析测速报文。

主流程必须为：

```python
def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


rows = stream_tshark_fields(
    tshark_path=tshark_path,
    capture=args.input,
    fields=EXTRACT_FIELDS,
    display_filter="tcp",
)
store = AnalysisStore(Path(args.analysis_db))
store.initialize()
accumulator = TcpAccumulator(
    interval_seconds=args.interval,
    event_sink=store.append_event,
)
for row in rows:
    accumulator.observe(row)
store.flush_events()
result = accumulator.finalize()
store.write_result(result)
write_json(Path(args.output_json), result.to_summary_dict())
write_json(Path(args.coverage_json), result.coverage.model_dump())
```

- [ ] **步骤 5：更新 run_pipeline**

流水线必须：

1. 发现 TShark；
2. 必要时将 pcap 转换为 pcapng；
3. 调用测速流筛选；
4. 对每个请求方向执行一次全量 TCP 提取；
5. 合并不同方向的 manifest，且不得覆盖文件；
6. 输出缺失时返回非零退出码；
7. 取消或超时时终止子进程；
8. 成功时将精确产物路径写入 `manifest.json`；
9. 失败时写入 `status="failed"`，错误码必须为 `INVALID_CAPTURE`、`NO_TCP_PACKETS`、`NO_SPEED_FLOW`、`ANALYSIS_TIMEOUT`、`ANALYSIS_FAILED` 或 `INVALID_ANALYSIS_OUTPUT`。

- [ ] **步骤 6：更新 skill 文档**

记录准确的新调用方式、依赖发现顺序、输出文件、全量报文语义以及 5000 报文限制的移除。

- [ ] **步骤 7：运行测试和手工冒烟命令**

```bash
python3 -m pytest tests/unit/test_tshark.py tests/unit/test_aggregate.py tests/unit/test_store.py tests/integration/test_real_pipeline.py -v
python3 speed-analyze/scripts/run_pipeline.py --help
```

预期：测试通过；如果缺少 TShark，集成测试必须明确跳过。帮助信息包含 `--analysis-id`、`--interval` 和 `--build-evidence-index`。

- [ ] **步骤 8：提交**

```bash
git add speed-analyze tests/integration/test_real_pipeline.py
git commit -m "feat: harden speed analysis for full captures"
```

---

### 任务 6：实现分析器 Adapter 和 FastMCP 工具

**文件：**
- 创建：`src/speed_agent/analyzer/base.py`
- 创建：`src/speed_agent/analyzer/mock.py`
- 创建：`src/speed_agent/analyzer/real.py`
- 创建：`src/speed_agent/mcp/server.py`
- 创建：`src/speed_agent/mcp/client.py`
- 创建：`tests/fixtures/mock_analysis.json`
- 创建：`tests/contract/test_mcp_tools.py`

**接口：**
- 产出：`AnalyzerAdapter.analyze(request, progress=None) -> AnalyzeResponse`
- 产出：`AnalyzerAdapter.get_evidence(request) -> EvidenceResponse`
- 产出 FastMCP 工具：`analyze_speed_capture` 和 `get_tcp_evidence`
- 产出：`SpeedMCPClient` 异步封装
- 产出：`mcp_server_path() -> str`

- [ ] **步骤 1：编写失败的契约测试**

```python
@pytest.mark.asyncio
async def test_analyze_tool_returns_structured_response(mcp_client, absolute_capture) -> None:
    result = await mcp_client.call_tool(
        "analyze_speed_capture",
        {
            "request": {
                "request_id": "contract-1",
                "pcap_path": str(absolute_capture),
                "target": "download",
            }
        },
    )
    response = AnalyzeResponse.model_validate(result.data)
    assert response.analysis_id == "contract-1"


@pytest.mark.asyncio
async def test_custom_query_rejects_shell_filter(mcp_client) -> None:
    result = await mcp_client.call_tool(
        "get_tcp_evidence",
        {
            "request": {
                "analysis_id": "contract-1",
                "evidence_type": "custom_packet_query",
                "query": {
                    "predicates": [
                        {"field": "frame.number; rm -rf /", "operator": "eq", "value": 1}
                    ]
                },
                "limit": 10,
            }
        },
    )
    assert result.is_error is True
```

- [ ] **步骤 2：确认测试失败**

```bash
python3 -m pytest tests/contract/test_mcp_tools.py -v
```

预期：由于 MCP Server/Client 模块尚不存在，测试失败。

- [ ] **步骤 3：实现 Adapter 协议**

```python
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from speed_agent.domain import AnalyzeRequest, AnalyzeResponse, EvidenceRequest, EvidenceResponse


ProgressCallback = Callable[[float, float | None, str | None], Awaitable[None]]


class AnalyzerAdapter(ABC):
    @abstractmethod
    async def analyze(
        self,
        request: AnalyzeRequest,
        progress: ProgressCallback | None = None,
    ) -> AnalyzeResponse:
        raise NotImplementedError

    @abstractmethod
    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        raise NotImplementedError
```

真实 Adapter 使用 `asyncio.create_subprocess_exec` 调用流水线，读取 JSONL 进度文件并校验 `manifest.json`，且不得使用 `shell=True`。

使用：

```python
def analysis_timeout_seconds(input_size_bytes: int) -> int:
    estimated = int(input_size_bytes / 20_000_000 * 4)
    return min(21_600, max(300, estimated))
```

打开任务独立的日志文件，将其作为 `stdout` 传入，并设置 `stderr=asyncio.subprocess.STDOUT`，避免流水线日志在内存中累积。使用该超时时间，通过 `asyncio.wait_for` 包装 `process.wait()`。发生超时或取消时，先调用 `process.terminate()`，等待五秒；如果子进程仍在运行，再调用 `process.kill()`。通过 `psutil.Process(process.pid)` 采样子进程 RSS，并将峰值写入 `resource_usage["peak_rss_bytes"]`。

进程退出后解析 `manifest.json`。如果 `status` 为 `failed`，使用清单中的原始错误码和建议操作抛出 `AppError`。如果进程退出后没有有效清单，则抛出 `INVALID_ANALYSIS_OUTPUT`。将 `asyncio.TimeoutError` 映射为 `ANALYSIS_TIMEOUT`，将任务取消映射为 `ANALYSIS_CANCELLED`。

启动流水线后创建后台 `tail_progress` 任务：

```python
async def tail_progress(
    progress_path: Path,
    process: asyncio.subprocess.Process,
    callback: ProgressCallback | None,
) -> None:
    offset = 0
    while process.returncode is None:
        if progress_path.exists():
            with progress_path.open("r", encoding="utf-8") as handle:
                handle.seek(offset)
                for line in handle:
                    event = json.loads(line)
                    if callback is not None:
                        await callback(
                            float(event.get("current") or 0),
                            (
                                float(event["total"])
                                if event.get("total") is not None
                                else None
                            ),
                            event.get("message"),
                        )
                offset = handle.tell()
        await asyncio.sleep(0.25)
```

子进程退出后取消并等待该任务结束，然后发送最终完成进度事件。

- [ ] **步骤 4：实现 FastMCP Server**

```python
from fastmcp import Context, FastMCP

from speed_agent.domain import AnalyzeRequest, AnalyzeResponse, EvidenceRequest, EvidenceResponse


def build_adapter_from_settings() -> AnalyzerAdapter:
    settings = Settings.load()
    artifacts = ArtifactManager(
        Path(settings.artifact_root),
        settings.artifact_ttl_hours,
    )
    if settings.speed_analyzer_mode == "mock":
        return MockSpeedAnalyzerAdapter.from_fixture(
            Path("tests/fixtures/mock_analysis.json")
        )
    return RealSpeedAnalyzerAdapter(settings=settings, artifacts=artifacts)


mcp = FastMCP("tcp-speed-analysis")
adapter = build_adapter_from_settings()


@mcp.tool
async def analyze_speed_capture(
    request: AnalyzeRequest,
    ctx: Context,
) -> AnalyzeResponse:
    async def progress(current: float, total: float | None, message: str | None) -> None:
        await ctx.report_progress(
            progress=current,
            total=total,
            message=message,
        )

    return await adapter.analyze(request, progress=progress)


@mcp.tool
async def get_tcp_evidence(request: EvidenceRequest) -> EvidenceResponse:
    return await adapter.get_evidence(request)


if __name__ == "__main__":
    mcp.run()
```

- [ ] **步骤 5：实现 stdio Client 封装**

使用 FastMCP 文档规定的异步 Client 生命周期：

```python
from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport


class SpeedMCPClient:
    def __init__(
        self,
        server_path: str,
        env: dict[str, str] | None = None,
        progress_handler=None,
    ) -> None:
        transport = PythonStdioTransport(server_path, env=env)
        self._client = Client(transport)
        self._progress_handler = progress_handler

    async def __aenter__(self) -> "SpeedMCPClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.__aexit__(exc_type, exc, tb)

    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        result = await self._client.call_tool(
            "analyze_speed_capture",
            {"request": request.model_dump(mode="json")},
            progress_handler=self._progress_handler,
        )
        return AnalyzeResponse.model_validate(result.data)

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        result = await self._client.call_tool(
            "get_tcp_evidence",
            {"request": request.model_dump(mode="json")},
        )
        return EvidenceResponse.model_validate(result.data)
```

实现：

```python
def mcp_server_path() -> str:
    return str(Path(__file__).resolve().with_name("server.py"))
```

- [ ] **步骤 6：运行契约测试**

```bash
python3 -m pytest tests/contract/test_mcp_tools.py -v
```

预期：两个工具都能校验结构化输入输出，并拒绝不安全查询。

- [ ] **步骤 7：提交**

```bash
git add src/speed_agent/analyzer src/speed_agent/mcp tests/contract tests/fixtures/mock_analysis.json
git commit -m "feat: expose speed analysis through fastmcp"
```

---

### 任务 7：构建上下文和开放式结构化诊断

**文件：**
- 创建：`src/speed_agent/context.py`
- 创建：`src/speed_agent/model.py`
- 创建：`src/speed_agent/prompts/hypothesis.md`
- 创建：`src/speed_agent/prompts/verification.md`
- 创建：`tests/unit/test_context.py`

**接口：**
- 产出：`ContextBuilder.build(standard_bandwidth_mbps: float, actual_bandwidth_mbps: float, analysis: AnalyzeResponse, evidence: list[EvidenceResponse]) -> DiagnosisContext`
- 产出：`DiagnosisModel.generate_hypotheses(context) -> HypothesisBatch`
- 产出：`DiagnosisModel.verify(context, hypotheses, evidence) -> VerificationResult`

- [ ] **步骤 1：编写失败的上下文测试**

```python
def make_analysis() -> AnalyzeResponse:
    intervals = [
        {
            "interval_start": float(index),
            "interval_end": float(index + 1),
            "throughput_mbps": 300.0,
            "anomaly_score": 0.0,
        }
        for index in range(100)
    ]
    intervals[-1] = {
        "interval_start": 99.0,
        "interval_end": 100.0,
        "throughput_mbps": 20.0,
        "anomaly_score": 0.95,
    }
    return AnalyzeResponse(
        analysis_id="context-1",
        status="completed",
        coverage_summary=CoverageSummary(
            input_size_bytes=10_000,
            total_packets_seen=10_000,
            tcp_packets_seen=9_000,
            speed_packets_analyzed=8_000,
            analyzed_bytes=8_000_000,
            analyzed_duration_seconds=100.0,
            complete=True,
            truncated=False,
        ),
        flow_summary={"flows": []},
        tcp_summary={"avg_throughput_mbps": 297.0},
        interval_summary=intervals,
        syn_options={},
        available_evidence=["io_timeline"],
        resource_usage={},
        warnings=[],
        artifact_paths={},
    )


def test_context_keeps_late_anomaly_and_coverage() -> None:
    context = ContextBuilder(max_intervals=20).build(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=300,
        analysis=make_analysis(),
        evidence=[],
    )
    assert context.coverage_summary.complete is True
    assert any(item["interval_start"] == 99 for item in context.anomaly_intervals)
    assert context.omitted_normal_intervals > 0


def test_context_does_not_include_raw_packet_payload() -> None:
    analysis = make_analysis()
    analysis.tcp_summary["tcp.payload"] = "secret"
    analysis.tcp_summary["per_packet_fields"] = [{"frame.number": 1}]
    context = ContextBuilder(max_intervals=20).build(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=300,
        analysis=analysis,
        evidence=[],
    )
    serialized = context.model_dump_json()
    assert "tcp.payload" not in serialized
    assert "per_packet_fields" not in serialized
```

- [ ] **步骤 2：确认测试失败**

```bash
python3 -m pytest tests/unit/test_context.py -v
```

预期：由于 `ContextBuilder` 尚不存在，测试失败。

- [ ] **步骤 3：实现确定性的上下文分层**

`DiagnosisContext` 必须包含：

- 带宽上下文和达标率；
- 覆盖范围摘要；
- 全局 TCP 指标；
- 每流摘要；
- 保留的异常时间区间；
- 正常时间区间压缩元数据；
- SYN 选项；
- 已收集证据；
- 证据覆盖范围和截断标记。

本组件不得直接将异常映射为原因。

- [ ] **步骤 4：编写假设生成 Prompt**

系统 Prompt 必须明确说明：

```text
Common TCP causes are a mandatory baseline checklist, not a whitelist.
Generate additional hypotheses from the actual anomaly facts and metric relationships.
For every hypothesis return supporting evidence, contradicting evidence,
missing evidence, affected flows, observability, confidence, and a verification request.
Never claim an outside-capture cause is proven by packet evidence.
If no hypothesis is sufficiently supported, allow the result to remain unresolved.
Do not output hidden chain-of-thought; output only structured findings.
```

- [ ] **步骤 5：实现 OpenAI 兼容的模型封装**

```python
from langchain_openai import ChatOpenAI


class DiagnosisModel:
    def __init__(self, settings: Settings) -> None:
        self._model = ChatOpenAI(
            model=settings.model_name,
            base_url=settings.model_base_url,
            api_key=settings.model_api_key,
            timeout=settings.model_timeout_seconds,
            max_retries=2,
            temperature=0,
        )
        self._hypothesis_model = self._model.with_structured_output(HypothesisBatch)
        self._verification_model = self._model.with_structured_output(VerificationResult)

    async def generate_hypotheses(self, context: DiagnosisContext) -> HypothesisBatch:
        messages = build_hypothesis_messages(context)
        return await self._hypothesis_model.ainvoke(messages)

    async def verify(
        self,
        context: DiagnosisContext,
        hypotheses: list[Hypothesis],
        evidence: list[EvidenceResponse],
    ) -> VerificationResult:
        messages = build_verification_messages(context, hypotheses, evidence)
        return await self._verification_model.ainvoke(messages)
```

加载两个包内 Prompt 文件，实现 `build_hypothesis_messages` 和 `build_verification_messages`，并且只序列化 `DiagnosisContext`、`Hypothesis` 和 `EvidenceResponse` 字段。

- [ ] **步骤 6：测试确定性的上下文行为**

任务 7 的测试不得调用外部模型 API。

```bash
python3 -m pytest tests/unit/test_context.py -v
```

预期：所有上下文压缩和敏感字段测试通过。

- [ ] **步骤 7：提交**

```bash
git add src/speed_agent/context.py src/speed_agent/model.py src/speed_agent/prompts tests/unit/test_context.py
git commit -m "feat: add open-ended evidence diagnosis model"
```

---

### 任务 8：实现有界的 LangGraph 工作流

**文件：**
- 创建：`src/speed_agent/graph.py`
- 创建：`tests/fakes.py`
- 创建：`tests/unit/test_graph.py`

**接口：**
- 消费：`SpeedMCPClient`、`DiagnosisModel`、`ArtifactManager`
- 产出：`GraphDependencies`
- 产出：`build_graph(dependencies) -> CompiledStateGraph`
- 产出节点：`collect`、`validate`、`analyze`、`reason`、`inspect_evidence`、`verify`、`report`

- [ ] **步骤 1：使用伪依赖编写路由测试**

```python
def valid_initial_state(tmp_path: Path) -> AgentState:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"pcapng-test-fixture")
    return {
        "pcap_path": str(capture),
        "standard_bandwidth_mbps": 1000.0,
        "actual_bandwidth_mbps": 300.0,
        "target": "download",
        "analysis_id": "graph-1",
        "inspection_count": 0,
        "collected_evidence": [],
    }


@pytest.mark.asyncio
async def test_graph_inspects_evidence_then_reports(fake_dependencies, tmp_path) -> None:
    graph = build_graph(fake_dependencies)
    result = await graph.ainvoke(valid_initial_state(tmp_path))
    assert result["inspection_count"] == 1
    assert result["final_report"]["primary_cause"] == "链路拥塞"


@pytest.mark.asyncio
async def test_graph_stops_after_three_inspections(fake_dependencies, tmp_path) -> None:
    fake_dependencies.model.always_requests_more_evidence = True
    result = await build_graph(fake_dependencies).ainvoke(valid_initial_state(tmp_path))
    assert result["inspection_count"] == 3
    assert result["final_report"]["confidence"] == "low"


@pytest.mark.asyncio
async def test_graph_returns_unresolved_when_all_hypotheses_fail(
    fake_dependencies,
    tmp_path,
) -> None:
    fake_dependencies.model.reject_all_hypotheses = True
    result = await build_graph(fake_dependencies).ainvoke(valid_initial_state(tmp_path))
    assert result["final_report"]["primary_cause"] == "unresolved"
```

- [ ] **步骤 2：确认测试失败**

```bash
python3 -m pytest tests/unit/test_graph.py -v
```

预期：由于 Graph 实现尚不存在，测试失败。

- [ ] **步骤 3：定义 Graph 状态**

为保证 LangGraph 性能，使用 `TypedDict` 定义状态：

```python
class AgentState(TypedDict, total=False):
    pcap_path: str
    standard_bandwidth_mbps: float
    actual_bandwidth_mbps: float
    target: str
    achievement_ratio_pct: float
    analysis_id: str
    analysis: dict[str, Any]
    diagnosis_context: dict[str, Any]
    hypotheses: list[dict[str, Any]]
    pending_evidence: list[dict[str, Any]]
    collected_evidence: Annotated[list[dict[str, Any]], operator.add]
    inspection_count: int
    verification: dict[str, Any]
    final_report: dict[str, Any]
    error: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class GraphDependencies:
    mcp_client: SpeedMCPClient
    model: DiagnosisModel
    artifacts: ArtifactManager
    paths: ArtifactPaths
```

在 `tests/fakes.py` 中使用：

```python
class FakeMCPClient:
    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        return make_complete_analysis(request.request_id)

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        return make_evidence_response(request.analysis_id, request.evidence_type)


class FakeDiagnosisModel:
    always_requests_more_evidence = False
    reject_all_hypotheses = False

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings

    async def generate_hypotheses(self, context: DiagnosisContext) -> HypothesisBatch:
        return make_hypothesis_batch(request_evidence=True)

    async def verify(
        self,
        context: DiagnosisContext,
        hypotheses: list[Hypothesis],
        evidence: list[EvidenceResponse],
    ) -> VerificationResult:
        if self.reject_all_hypotheses:
            return make_unresolved_verification()
        if self.always_requests_more_evidence:
            return make_more_evidence_verification()
        return make_accepted_verification("链路拥塞")


@pytest.fixture
def fake_dependencies(tmp_path: Path) -> GraphDependencies:
    artifacts = ArtifactManager(tmp_path / "output", ttl_hours=24)
    paths = artifacts.create("graph-1")
    return GraphDependencies(
        mcp_client=FakeMCPClient(),
        model=FakeDiagnosisModel(),
        artifacts=artifacts,
        paths=paths,
    )
```

在同一个测试文件中定义辅助函数：

```python
def make_complete_analysis(analysis_id: str) -> AnalyzeResponse:
    return AnalyzeResponse(
        analysis_id=analysis_id,
        status="completed",
        coverage_summary=CoverageSummary(
            input_size_bytes=1000,
            total_packets_seen=100,
            tcp_packets_seen=100,
            speed_packets_analyzed=100,
            analyzed_bytes=100_000,
            analyzed_duration_seconds=10.0,
            complete=True,
            truncated=False,
        ),
        flow_summary={"flows": [{"flow_id": "flow-1"}]},
        tcp_summary={"retransmission_rate_pct": 5.0},
        interval_summary=[],
        syn_options={},
        available_evidence=["retransmissions"],
        resource_usage={},
        warnings=[],
        artifact_paths={},
    )


def make_evidence_response(analysis_id: str, evidence_type: str) -> EvidenceResponse:
    return EvidenceResponse(
        analysis_id=analysis_id,
        evidence_type=evidence_type,
        summary={"matching_packets": 5},
        items=[{"evidence_id": "event-1", "frame_number": 10}],
        total=1,
        next_offset=None,
        truncated=False,
        source="analysis.sqlite",
        coverage_range={"time_start": 0.0, "time_end": 10.0},
        warnings=[],
    )


def make_hypothesis() -> Hypothesis:
    return Hypothesis(
        cause="链路拥塞",
        hypothesis_type="known_pattern",
        observability="direct",
        confidence="medium",
        supporting_evidence=["retransmission_rate_pct=5.0"],
        contradicting_evidence=[],
        missing_evidence=["retransmission timeline"],
        affected_flows=["flow-1"],
        explanation="重传与吞吐下降相关",
        suggestion="检查链路队列和丢包",
    )


def make_hypothesis_batch(request_evidence: bool) -> HypothesisBatch:
    request = EvidenceRequest(
        analysis_id="graph-1",
        evidence_type="retransmissions",
        limit=100,
    )
    return HypothesisBatch(
        hypotheses=[make_hypothesis()],
        requested_evidence=[request] if request_evidence else [],
    )


def make_unresolved_verification() -> VerificationResult:
    return VerificationResult(
        accepted_hypotheses=[],
        rejected_causes=["链路拥塞"],
        requested_evidence=[],
        ready_for_report=True,
        confidence="low",
        limitations=["现有证据不足"],
    )


def make_more_evidence_verification() -> VerificationResult:
    return VerificationResult(
        accepted_hypotheses=[make_hypothesis()],
        rejected_causes=[],
        requested_evidence=[
            EvidenceRequest(
                analysis_id="graph-1",
                evidence_type="retransmissions",
                limit=100,
            )
        ],
        ready_for_report=False,
        confidence="medium",
        limitations=[],
    )


def make_accepted_verification(cause: str) -> VerificationResult:
    hypothesis = make_hypothesis().model_copy(update={"cause": cause})
    return VerificationResult(
        accepted_hypotheses=[hypothesis],
        rejected_causes=[],
        requested_evidence=[],
        ready_for_report=True,
        confidence="high",
        limitations=[],
    )
```

- [ ] **步骤 4：实现节点和条件路由**

```python
builder = StateGraph(AgentState)
builder.add_node("validate", nodes.validate)
builder.add_node("analyze", nodes.analyze)
builder.add_node("reason", nodes.reason)
builder.add_node("inspect_evidence", nodes.inspect_evidence)
builder.add_node("verify", nodes.verify)
builder.add_node("report", nodes.report)

builder.add_edge(START, "validate")
builder.add_conditional_edges(
    "validate",
    route_after_validate,
    {"analyze": "analyze", "error": END},
)
builder.add_edge("analyze", "reason")
builder.add_conditional_edges(
    "reason",
    route_after_reason,
    {"inspect": "inspect_evidence", "verify": "verify"},
)
builder.add_edge("inspect_evidence", "verify")
builder.add_conditional_edges(
    "verify",
    route_after_verify,
    {"inspect": "inspect_evidence", "report": "report"},
)
builder.add_edge("report", END)
graph = builder.compile()
```

当 `inspection_count >= 3` 时，`route_after_verify` 必须返回 `report`。

- [ ] **步骤 5：在每个节点执行后持久化轨迹事件**

每个节点写入：

- 节点名称；
- 分析 ID；
- 时间戳；
- 工具调用名称；
- 证据 ID；
- 发生变化的状态字段；
- 错误元数据。

不得写入 API Key、原始 Payload、模型隐藏推理或完整逐包记录。

- [ ] **步骤 6：运行 Graph 测试**

```bash
python3 -m pytest tests/unit/test_graph.py -v
```

预期：正常路由、三轮上限、错误路由、覆盖不完整和 `unresolved` 测试全部通过。

- [ ] **步骤 7：提交**

```bash
git add src/speed_agent/graph.py tests/fakes.py tests/unit/test_graph.py
git commit -m "feat: add bounded evidence diagnosis graph"
```

---

### 任务 9：增加报告渲染和 CLI 入口

**文件：**
- 创建：`src/speed_agent/report.py`
- 创建：`src/speed_agent/cli.py`
- 创建：`tests/integration/test_cli.py`
- 创建：`README.md`

**接口：**
- 产出：`render_terminal_report(report) -> str`
- 产出：`save_report(paths, report) -> Path`
- 产出：`run_diagnosis(settings, pcap_path, standard, actual, target, keep_artifacts) -> int`
- 产出命令：`speed-agent diagnose PATH --standard FLOAT --actual FLOAT --target TARGET`

- [ ] **步骤 1：编写失败的 CLI 测试**

```python
from typer.testing import CliRunner

from speed_agent.cli import app
from tests.fakes import FakeDiagnosisModel


def test_cli_writes_json_report(monkeypatch, tmp_path, sample_capture) -> None:
    monkeypatch.setenv("SPEED_ANALYZER_MODE", "mock")
    monkeypatch.setenv("ARTIFACT_ROOT", str(tmp_path / "output"))
    monkeypatch.setenv("MODEL_BASE_URL", "http://127.0.0.1:1/v1")
    monkeypatch.setenv("MODEL_API_KEY", "unused")
    monkeypatch.setenv("MODEL_NAME", "unused")
    monkeypatch.setattr("speed_agent.cli.DiagnosisModel", FakeDiagnosisModel)
    result = CliRunner().invoke(
        app,
        [
            "diagnose",
            str(sample_capture),
            "--standard",
            "1000",
            "--actual",
            "300",
            "--target",
            "download",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "达标率" in result.output
    assert list((tmp_path / "output").glob("*/report.json"))
```

- [ ] **步骤 2：确认测试失败**

```bash
python3 -m pytest tests/integration/test_cli.py -v
```

预期：由于 CLI 尚不存在，测试失败。

- [ ] **步骤 3：实现报告渲染**

终端报告包含：

1. 带宽和达标率；
2. 覆盖范围状态；
3. 主要原因或 `unresolved`；
4. 排序后的候选原因；
5. 支持证据和反向证据；
6. 局限性；
7. 排障步骤；
8. 产物目录。

使用 `DiagnosticReport.model_dump(mode="json")` 写入 `report.json`。

- [ ] **步骤 4：实现 Typer CLI**

```python
from datetime import datetime, timezone
from typing import Annotated

app = typer.Typer(no_args_is_help=True)


@app.command()
def diagnose(
    pcap_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    standard: Annotated[float, typer.Option(min=0.000001)],
    actual: Annotated[float, typer.Option(min=0.000001)],
    target: Annotated[Target, typer.Option()] = Target.DOWNLOAD,
    keep_artifacts: Annotated[bool, typer.Option()] = False,
) -> None:
    settings = Settings.load()
    exit_code = asyncio.run(
        run_diagnosis(
            settings=settings,
            pcap_path=pcap_path.resolve(),
            standard=standard,
            actual=actual,
            target=target,
            keep_artifacts=keep_artifacts,
        )
    )
    raise typer.Exit(exit_code)


async def run_diagnosis(
    settings: Settings,
    pcap_path: Path,
    standard: float,
    actual: float,
    target: Target,
    keep_artifacts: bool,
) -> int:
    manager = ArtifactManager(Path(settings.artifact_root), settings.artifact_ttl_hours)
    manager.cleanup_expired(datetime.now(timezone.utc))
    manager.preflight(pcap_path, target.value)
    request_id = create_request_id()
    paths = manager.create(request_id)
    if keep_artifacts:
        manager.mark_keep(paths)

    async def progress_handler(
        progress: float,
        total: float | None,
        message: str | None,
    ) -> None:
        if total:
            typer.echo(f"[{progress / total * 100:5.1f}%] {message or ''}")
        else:
            typer.echo(f"[{progress:.0f}] {message or ''}")

    async with SpeedMCPClient(
        server_path=mcp_server_path(),
        env=os.environ.copy(),
        progress_handler=progress_handler,
    ) as client:
        dependencies = GraphDependencies(
            mcp_client=client,
            model=DiagnosisModel(settings),
            artifacts=manager,
            paths=paths,
        )
        result = await build_graph(dependencies).ainvoke(
            {
                "pcap_path": str(pcap_path),
                "standard_bandwidth_mbps": standard,
                "actual_bandwidth_mbps": actual,
                "target": target.value,
                "analysis_id": request_id,
                "inspection_count": 0,
                "collected_evidence": [],
            }
        )
    if result.get("error"):
        typer.echo(result["error"]["message"], err=True)
        return 2
    report = DiagnosticReport.model_validate(result["final_report"])
    save_report(paths, report)
    typer.echo(render_terminal_report(report))
    return 0


if __name__ == "__main__":
    app()
```

展示 MCP 流水线的阶段进度，但不得打印子进程原始输出。

使用 `speed_agent.artifacts` 中的 `create_request_id`，以及 `speed_agent.mcp.client` 中的 `mcp_server_path`。

- [ ] **步骤 5：编写 README 使用说明**

记录：

- 依赖安装；
- TShark 发现和 `TSHARK_PATH`；
- 模型环境变量；
- Real 和 Mock 模式；
- CLI 命令；
- 输出目录结构；
- 隐私边界；
- 性能测试命令。

- [ ] **步骤 6：运行 CLI 测试**

```bash
python3 -m pytest tests/integration/test_cli.py -v
python3 -m speed_agent.cli --help
```

预期：CLI 测试通过，帮助信息列出 `diagnose` 命令。

- [ ] **步骤 7：提交**

```bash
git add src/speed_agent/report.py src/speed_agent/cli.py tests/integration/test_cli.py README.md
git commit -m "feat: add diagnosis cli and reports"
```

---

### 任务 10：增加端到端、安全和大报文发布门禁

**文件：**
- 创建：`scripts/generate_test_capture.py`
- 创建：`tests/performance/test_large_capture.py`
- 修改：`tests/integration/test_real_pipeline.py`
- 修改：`tests/integration/test_cli.py`
- 修改：`README.md`

**接口：**
- 产出命令：`python3 scripts/generate_test_capture.py --output PATH --size-mb 500`
- 消费：外部 `PERF_PCAP_PATH`，用于 2 GB 发布门禁。

- [ ] **步骤 1：增加确定性的合成报文生成器**

生成：

- 至少两个并行 TCP 测速流；
- 开始阶段的正常报文；
- 第 5000 个报文之后的一段重传/重复 ACK 突发；
- 可选的零窗口时间区间；
- 跨度至少 10 秒的时间戳。

脚本接收 `--output`、`--size-mb` 和 `--seed` 参数，并在本地写入 pcapng 文件。

- [ ] **步骤 2：增加默认端到端回归测试**

断言：

- `analysis.sqlite` 中包含后段异常；
- 覆盖范围完整且未截断；
- 流摘要中包含多个测速流；
- 模型上下文不包含原始 Payload；
- Graph 执行了证据检索；
- 报告引用了证据 ID；
- 日志中不包含 API Key。

- [ ] **步骤 3：增加可选执行的 2 GB 性能测试**

```python
@pytest.mark.performance
def test_large_capture_stays_within_resource_budget(tmp_path: Path) -> None:
    capture_value = os.environ.get("PERF_PCAP_PATH")
    if not capture_value:
        pytest.skip("PERF_PCAP_PATH is not configured")
    capture = Path(capture_value)
    assert capture.stat().st_size >= 2 * 1024**3
    settings = Settings(
        model_base_url="http://127.0.0.1:1/v1",
        model_api_key="unused",
        model_name="unused",
        artifact_root=str(tmp_path / "output"),
        speed_analyzer_mode="real",
    )
    artifacts = ArtifactManager(Path(settings.artifact_root), ttl_hours=24)
    adapter = RealSpeedAnalyzerAdapter(settings=settings, artifacts=artifacts)
    response = asyncio.run(
        adapter.analyze(
            AnalyzeRequest(
                request_id="performance-2gb",
                pcap_path=capture.resolve(),
                target="download",
                aggregation_interval_seconds=1,
                build_evidence_index=True,
            )
        )
    )
    memory_budget = int(os.environ.get("PERF_MAX_RSS_BYTES", str(1024**3)))
    assert response.coverage_summary.complete is True
    assert response.coverage_summary.truncated is False
    assert response.resource_usage["peak_rss_bytes"] < memory_budget
```

- [ ] **步骤 4：运行完整的默认测试套件**

```bash
python3 -m pytest -m "not performance" -v
python3 -m ruff check src speed-analyze/scripts tests scripts
```

预期：所有非性能测试通过；只有在 TShark 不可用时，真实集成测试才允许跳过。

- [ ] **步骤 5：在具备大报文夹具的机器上运行发布性能门禁**

```bash
export PERF_PCAP_PATH="$HOME/test-data/2gb-test.pcapng"
export PERF_MAX_RSS_BYTES=1073741824
test -f "$PERF_PCAP_PATH"
python3 -m pytest tests/performance/test_large_capture.py -v -m performance
```

预期：覆盖范围完整、无截断、未发生内存不足，且峰值内存低于配置的预算。

- [ ] **步骤 6：运行一次真实 CLI 冒烟诊断**

```bash
export SMOKE_PCAP_PATH="$HOME/test-data/sample.pcapng"
test -f "$SMOKE_PCAP_PATH"
MODEL_BASE_URL=http://127.0.0.1:8000/v1 \
MODEL_API_KEY=test-key \
MODEL_NAME=test-model \
speed-agent diagnose "$SMOKE_PCAP_PATH" \
  --standard 1000 \
  --actual 300 \
  --target download
```

预期：同一个分析目录下生成终端报告、`report.json`、`coverage.json`、`analysis.sqlite` 和 `trace.jsonl`。

- [ ] **步骤 7：提交**

```bash
git add scripts tests/performance tests/integration README.md
git commit -m "test: add end-to-end and large-capture gates"
```

---

## 最终验证

- [ ] 运行所有默认测试：

```bash
python3 -m pytest -m "not performance" -v
```

- [ ] 运行代码检查：

```bash
python3 -m ruff check src speed-analyze/scripts tests scripts
```

- [ ] 确认不存在带数量上限的提取逻辑：

```bash
rg -- "-c|max-packets|per_packet_fields" speed-analyze/scripts
```

预期：基础分析中不存在生效的报文数量上限，也不存在完整逐包 JSON 输出。

- [ ] 验证 Shell 安全性：

```bash
rg -n "shell=True|os\\.system|subprocess\\..*\\(.*shell" src speed-analyze/scripts
```

预期：无匹配结果。

- [ ] 检查最终 Git 差异和状态：

```bash
git status --short
git log --oneline --decorate -10
```

预期：只保留用户有意留下的修改；实施提交按照任务顺序存在。
