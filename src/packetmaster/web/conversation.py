"""Web 会话编排：提取参数、脱敏消息，并将报文统一替换为内部引用。"""

from __future__ import annotations

import re
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any

from packetmaster.chat import ConversationRoute, route_conversation
from packetmaster.domain import (
    ConversationTurn,
    DiagnosisIntent,
    PathReference,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.intent import (
    extract_capture_paths,
    extract_contextual_values,
    extract_explicit_bandwidth,
    merge_intent,
)
from packetmaster.llm_observability import LLMObservationCollector
from packetmaster.web.captures import CaptureRegistry
from packetmaster.web.contracts import (
    AnalysisMode,
    AnalysisSummary,
    CaptureSummary,
    ChatTurnResult,
    ConversationResult,
    DiagnosisParameters,
    MessageType,
    MissingParameter,
    Page,
    RagMessageCitation,
    SessionDetail,
    SessionSummary,
    TaskStatus,
)
from packetmaster.web.database import (
    MessageRepository,
    PendingIntentRecord,
    PendingIntentRepository,
    SessionRepository,
)
from packetmaster.web.tasks import AnalysisTaskRepository

_SECRET = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{12,}|(?:api[_-]?key|authorization)\s*[:=]\s*\S+)"
)
_ABSOLUTE_PATH = re.compile(
    r"(?i)(?<!\w)(?:[a-z]:[\\/]|/users/|/home/|/private/|/tmp/|~[/\\])"
    r"[^\n，。；,;!?]*"
)
_TITLE_PREFIX = re.compile(
    r"^(?:你好[，,。!！\s]*|请问[，,：:\s]*|请帮我|帮我|麻烦(?:帮我)?|"
    r"我想(?:了解|知道|问一下)|请(?:分析|解释|看看|检查)|分析(?:一下)?)"
)
_LOW_INFORMATION = re.compile(
    r"^(?:你好|您好|嗨|hi|hello|谢谢|好的|可以|确认|继续|重试|\d+(?:\.\d+)?[a-z]*)[。.!！]?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _GeneralKnowledgeTrace:
    bundle: Any | None = None
    status: str | None = None
    reason: str = ""
    citations: list[RagMessageCitation] = field(default_factory=list)


class WebConversationService:
    """协调对话、待补全参数、报文引用与分析任务创建。"""

    def __init__(
        self,
        *,
        sessions: SessionRepository,
        messages: MessageRepository,
        intents: PendingIntentRepository,
        captures: CaptureRegistry,
        tasks: AnalysisTaskRepository,
        model: Any,
        rag_runtime: Any | None = None,
        llm_observer: LLMObservationCollector | None = None,
        analysis_chat: Any | None = None,
    ) -> None:
        self.sessions = sessions
        self.messages = messages
        self.intents = intents
        self.captures = captures
        self.tasks = tasks
        self.model = model
        self.rag_runtime = rag_runtime
        self.llm_observer = llm_observer
        self.analysis_chat = analysis_chat

    def create_session(self, *, title: str = "新会话") -> SessionSummary:
        return self.sessions.create(title=title)

    def list_sessions(
        self, *, offset: int = 0, limit: int = 50
    ) -> Page[SessionSummary]:
        items, total = self.sessions.list(offset=offset, limit=limit)
        return Page(items=items, total=total, offset=offset, limit=limit)

    def session_detail(
        self, session_id: str, *, offset: int = 0, limit: int = 100
    ) -> SessionDetail:
        session = self._session(session_id)
        items, total = self.messages.list(
            session_id=session_id, offset=offset, limit=limit
        )
        return SessionDetail(
            session=session,
            messages=Page(items=items, total=total, offset=offset, limit=limit),
            parameters=self._parameters(self.intents.get(session_id)),
        )

    def delete_session(self, session_id: str) -> bool:
        if not self.sessions.delete(session_id):
            raise _not_found("SESSION_NOT_FOUND", "会话不存在")
        return True

    def register_capture(self, path: str) -> CaptureSummary:
        return self.captures.register(path)

    async def submit_message(
        self,
        session_id: str,
        *,
        content: str,
        capture_id: str | None = None,
        mode: AnalysisMode = AnalysisMode.SPEED,
    ) -> ConversationResult:
        scope = (
            self.llm_observer.scope(f"session-{session_id}")
            if self.llm_observer is not None
            else nullcontext([])
        )
        with scope:
            # 已选 capture_id 强制走诊断分支，避免普通闲聊路由丢失报文绑定。
            session = self._session(session_id)
            previous = self.intents.get(session_id)
            route = route_conversation(
                content,
                has_analysis=session.current_analysis_id is not None,
                has_pending_intent=previous is not None,
            )
            if capture_id is not None and session.current_analysis_id is None:
                route = ConversationRoute.DIAGNOSIS
            if route is ConversationRoute.GENERAL:
                result = await self._general(session_id, content)
            elif route is ConversationRoute.ANALYSIS_QUESTION:
                result = await self._analysis_question(session_id, content)
            else:
                result = await self._diagnosis(
                    session_id,
                    content=content,
                    capture_id=capture_id,
                    previous=previous,
                    mode=mode,
                )
            title = _conversation_title(content, has_capture=capture_id is not None)
            if title is not None:
                self.sessions.set_title_if_default(session_id, title)
            return result

    def confirm(self, session_id: str) -> AnalysisSummary:
        # 使用会话和待处理记录派生稳定 ID；重复点击确认会返回同一任务。
        self._session(session_id)
        pending = self.intents.get(session_id)
        if pending is None:
            raise _not_ready("当前会话还没有待确认的诊断参数")
        if pending.confirmed_analysis_id is not None:
            existing = self.tasks.get(pending.confirmed_analysis_id)
            if existing is not None:
                return existing
        parameters = self._parameters(pending)
        if not parameters.ready_for_confirmation or pending.capture_id is None:
            raise _not_ready("诊断参数尚未补充完整")
        analysis_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"packetmaster:{session_id}:{pending.updated_at.isoformat()}",
        ).hex
        try:
            analysis = self.tasks.create_queued(
                session_id=session_id,
                capture_id=pending.capture_id,
                standard_bandwidth_mbps=pending.standard_bandwidth_mbps,
                actual_bandwidth_mbps=pending.actual_bandwidth_mbps,
                target=pending.target,
                analysis_id=analysis_id,
            )
        except AppError as exc:
            existing = self.tasks.get(analysis_id)
            if exc.code != "ANALYSIS_ALREADY_ACTIVE" or existing is None:
                raise
            analysis = existing
        self.intents.mark_confirmed(session_id, analysis.analysis_id)
        self.messages.append(
            session_id=session_id,
            message_type=MessageType.CONFIRMATION,
            content="已确认诊断参数，任务已进入分析队列。",
            analysis_id=analysis.analysis_id,
        )
        return analysis

    async def _general(self, session_id: str, content: str) -> ConversationResult:
        safe_content = _redact(content)
        history = self._conversation_turns(session_id)
        self.messages.append(
            session_id=session_id,
            message_type=MessageType.USER,
            content=safe_content,
        )
        knowledge = await self._general_knowledge(safe_content)
        if knowledge.bundle is None:
            answer = await self.model.general_chat(safe_content, "", history)
        else:
            answer = await self.model.general_chat(
                safe_content, "", history, knowledge=knowledge.bundle
            )
        assistant = self.messages.append(
            session_id=session_id,
            message_type=MessageType.ASSISTANT,
            content=_redact(answer.answer),
            rag_status=knowledge.status,
            rag_reason=knowledge.reason,
            rag_citations=knowledge.citations,
        )
        return ConversationResult(route="general", assistant_message=assistant)

    async def _general_knowledge(self, question: str):
        if self.rag_runtime is None:
            return _GeneralKnowledgeTrace()
        try:
            query = self.rag_runtime.query_builder.build_general_chat(question)
            if query is None:
                return _GeneralKnowledgeTrace()
            bundle = await self.rag_runtime.retriever.retrieve(query)
            warnings = list(bundle.warnings)
            is_active = self.rag_runtime.mode.value == "active"
            degraded = bool(warnings) or not bundle.results or not is_active
            reranker_degraded = any("重排序降级" in warning for warning in warnings)
            reranker = getattr(self.rag_runtime.retriever, "reranker", None)
            citations = [
                RagMessageCitation(
                    knowledge_id=item.knowledge_id,
                    title=item.title,
                    chunk_id=item.chunk_id,
                    reranker_score=(
                        item.rerank_score
                        if reranker is not None and not reranker_degraded
                        else None
                    ),
                )
                for item in bundle.results
            ]
            if warnings:
                reason = "；".join(warnings)
            elif not bundle.results:
                reason = "RAG_NO_RESULTS"
            elif not is_active:
                reason = "RAG_MODE_NOT_ACTIVE"
            else:
                reason = ""
            return _GeneralKnowledgeTrace(
                bundle=bundle if is_active and bundle.results else None,
                status="degraded" if degraded else "used",
                reason=reason,
                citations=citations,
            )
        except Exception as exc:
            # General conversation remains available when knowledge retrieval degrades.
            reason = exc.code if isinstance(exc, AppError) else "RAG_RETRIEVAL_FAILED"
            return _GeneralKnowledgeTrace(status="degraded", reason=reason)

    async def _analysis_question(
        self, session_id: str, content: str
    ) -> ConversationResult:
        session = self._session(session_id)
        analysis_id = session.current_analysis_id
        analysis = self.tasks.get(analysis_id) if analysis_id is not None else None
        if (
            analysis is not None
            and analysis.status in {TaskStatus.COMPLETED, TaskStatus.PARTIAL}
            and self.analysis_chat is not None
        ):
            turn: ChatTurnResult = await self.analysis_chat.ask(
                analysis.analysis_id, content
            )
            return ConversationResult(
                route="analysis_question",
                chat_turn=turn,
            )
        self.messages.append(
            session_id=session_id,
            message_type=MessageType.USER,
            content=_redact(content),
        )
        assistant = self.messages.append(
            session_id=session_id,
            message_type=MessageType.ASSISTANT,
            content="任务正在分析中。报告生成后可继续追问原因、证据和建议。",
        )
        return ConversationResult(
            route="analysis_question", assistant_message=assistant
        )

    async def _diagnosis(
        self,
        session_id: str,
        *,
        content: str,
        capture_id: str | None,
        previous: PendingIntentRecord | None,
        mode: AnalysisMode,
    ) -> ConversationResult:
        # 文本中的路径仅在本机注册后使用，写入会话前始终替换和脱敏。
        extracted = extract_capture_paths(content)
        selected_capture = (
            self.captures.summary(capture_id) if capture_id is not None else None
        )
        ambiguities = list(previous.ambiguities if previous else [])
        registered: list[CaptureSummary] = []
        for local_path in extracted.registry.values().values():
            registered.append(self.captures.register(local_path))
        if len(registered) == 1:
            selected_capture = registered[0]
            ambiguities = [item for item in ambiguities if item != "检测到多个报文路径"]
        elif len(registered) > 1:
            selected_capture = None
            ambiguities.append("检测到多个报文路径，请只选择一个报文")

        safe_content = extracted.sanitized_text
        for reference, capture in zip(extracted.references, registered, strict=True):
            safe_content = safe_content.replace(reference.placeholder, "[已注册报文]")
        safe_content = _redact(safe_content)
        self.messages.append(
            session_id=session_id,
            message_type=MessageType.USER,
            content=safe_content,
        )

        previous_domain = _domain_intent(previous)
        local_values: dict[str, Any] = extract_explicit_bandwidth(content)
        for key, value in extract_contextual_values(content, previous_domain).items():
            local_values.setdefault(key, value)
        current = DiagnosisIntent(**local_values)
        intent = merge_intent(previous_domain, current)
        # 正则规则优先；只有没有确定参数时才请求模型补充意图，降低不确定性。
        if not local_values and hasattr(self.model, "parse_intent"):
            try:
                intent, _ = await self.model.parse_intent(safe_content, previous_domain)
            except AppError:
                pass
        capture_value = selected_capture or (
            self.captures.summary(previous.capture_id)
            if previous is not None and previous.capture_id is not None
            else None
        )
        if capture_value is not None:
            intent.capture = _capture_reference(capture_value.capture_id)
        intent = merge_intent(previous_domain, intent)
        if len(registered) == 1:
            intent.ambiguities = [
                item for item in intent.ambiguities if "多个报文路径" not in item
            ]
        intent.ambiguities = list(dict.fromkeys([*intent.ambiguities, *ambiguities]))
        stored = self.intents.upsert(
            session_id=session_id,
            capture_id=capture_value.capture_id if capture_value else None,
            standard_bandwidth_mbps=intent.standard_bandwidth_mbps,
            actual_bandwidth_mbps=intent.actual_bandwidth_mbps,
            target=intent.target or Target.DOWNLOAD,
            mode=mode,
            assumptions=(
                ["通用卡顿分析不要求提供带宽"]
                if mode is AnalysisMode.STALL
                else ["未填写带宽单位时默认按 Mbps 解释"]
            ),
            ambiguities=intent.ambiguities,
        )
        parameters = self._parameters(stored)
        if mode is AnalysisMode.STALL and capture_value is not None:
            analysis_id = uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"packetmaster:stall:{session_id}:{stored.updated_at.isoformat()}",
            ).hex
            try:
                analysis = self.tasks.create_queued(
                    session_id=session_id,
                    capture_id=capture_value.capture_id,
                    standard_bandwidth_mbps=1.0,
                    actual_bandwidth_mbps=1.0,
                    target=Target.BOTH,
                    mode=AnalysisMode.STALL,
                    analysis_context=_stall_context_text(safe_content),
                    analysis_id=analysis_id,
                )
            except AppError as exc:
                existing = self.tasks.get(analysis_id)
                if exc.code != "ANALYSIS_ALREADY_ACTIVE" or existing is None:
                    raise
                analysis = existing
            self.intents.mark_confirmed(session_id, analysis.analysis_id)
            assistant = self.messages.append(
                session_id=session_id,
                message_type=MessageType.CONFIRMATION,
                content="卡顿报文已接收，任务已进入分析队列。",
                analysis_id=analysis.analysis_id,
            )
            return ConversationResult(
                route="diagnosis",
                assistant_message=assistant,
                parameters=parameters,
                analysis=analysis,
            )
        status = (
            TaskStatus.AWAITING_CONFIRMATION
            if parameters.ready_for_confirmation
            else TaskStatus.DRAFT
        )
        self.sessions.set_status(session_id, status)
        assistant = self.messages.append(
            session_id=session_id,
            message_type=(
                MessageType.CONFIRMATION
                if parameters.ready_for_confirmation
                else MessageType.CLARIFICATION
            ),
            content=_parameter_message(parameters),
        )
        return ConversationResult(
            route="diagnosis",
            assistant_message=assistant,
            parameters=parameters,
        )

    def _parameters(
        self, pending: PendingIntentRecord | None
    ) -> DiagnosisParameters | None:
        if pending is None:
            return None
        capture = (
            self.captures.summary(pending.capture_id)
            if pending.capture_id is not None
            else None
        )
        missing: list[MissingParameter] = []
        if capture is None:
            missing.append(MissingParameter.CAPTURE)
        if (
            pending.mode is AnalysisMode.SPEED
            and pending.standard_bandwidth_mbps is None
        ):
            missing.append(MissingParameter.STANDARD_BANDWIDTH)
        if pending.mode is AnalysisMode.SPEED and pending.actual_bandwidth_mbps is None:
            missing.append(MissingParameter.ACTUAL_BANDWIDTH)
        # 卡顿任务在绑定报文后自动入队，不需要进入测速参数确认阶段。
        ready = (
            pending.mode is AnalysisMode.SPEED
            and not missing
            and not pending.ambiguities
        )
        return DiagnosisParameters(
            capture=capture,
            mode=pending.mode,
            standard_bandwidth_mbps=pending.standard_bandwidth_mbps,
            actual_bandwidth_mbps=pending.actual_bandwidth_mbps,
            target=pending.target,
            missing=missing,
            assumptions=pending.assumptions,
            ambiguities=pending.ambiguities,
            ready_for_confirmation=ready,
        )

    def _session(self, session_id: str) -> SessionSummary:
        session = self.sessions.get(session_id)
        if session is None:
            raise _not_found("SESSION_NOT_FOUND", "会话不存在")
        return session

    def _conversation_turns(self, session_id: str) -> list[ConversationTurn]:
        messages, _ = self.messages.list(session_id=session_id, limit=100)
        turns: list[ConversationTurn] = []
        question: str | None = None
        for message in messages:
            if message.message_type is MessageType.USER:
                question = message.content
            elif message.message_type is MessageType.ASSISTANT and question is not None:
                turns.append(
                    ConversationTurn(question=question, answer=message.content)
                )
                question = None
        return turns[-8:]


def _domain_intent(record: PendingIntentRecord | None) -> DiagnosisIntent | None:
    if record is None:
        return None
    return DiagnosisIntent(
        capture=_capture_reference(record.capture_id) if record.capture_id else None,
        standard_bandwidth_mbps=record.standard_bandwidth_mbps,
        actual_bandwidth_mbps=record.actual_bandwidth_mbps,
        target=record.target,
        ambiguities=record.ambiguities,
    )


def _capture_reference(capture_id: str) -> PathReference:
    return PathReference(placeholder=f"capture_{capture_id[:8]}")


def _stall_context_text(content: str) -> str:
    """Keep a bounded, redacted symptom description for deterministic tagging."""
    normalized = " ".join(content.split()).strip()
    if normalized == "请对所选报文进行通用卡顿分析":
        return ""
    return normalized[:500]


def _parameter_message(parameters: DiagnosisParameters) -> str:
    if parameters.ambiguities:
        details = "；".join(parameters.ambiguities)
        return f"参数存在歧义：{details}。请修正后再确认。"
    if parameters.mode is AnalysisMode.STALL:
        if parameters.capture is None:
            return "通用卡顿分析无需提供带宽，请先提供要分析的 pcap 或 pcapng 报文。"
        return "已选择通用卡顿分析，已绑定报文，将直接开始分析。"
    prompts = {
        MissingParameter.CAPTURE: "请提供要分析的 pcap 或 pcapng 报文绝对路径。",
        MissingParameter.STANDARD_BANDWIDTH: (
            "请提供标准带宽，例如 1000 Mbps；不写单位时按 Mbps 解释。"
        ),
        MissingParameter.ACTUAL_BANDWIDTH: (
            "请提供实际测速带宽，例如 20 Mbps；不写单位时按 Mbps 解释。"
        ),
    }
    if parameters.missing:
        return prompts[parameters.missing[0]]
    direction = {
        Target.DOWNLOAD: "下载",
        Target.UPLOAD: "上行",
        Target.BOTH: "上行和下载",
    }[parameters.target]
    return (
        f"参数已完整：标准带宽 {parameters.standard_bandwidth_mbps:g} Mbps，"
        f"实际带宽 {parameters.actual_bandwidth_mbps:g} Mbps，分析{direction}方向。"
        "请确认后启动分析。"
    )


def _conversation_title(value: str, *, has_capture: bool = False) -> str | None:
    cleaned = re.sub(r"\s+", " ", _redact(value)).strip()
    if _LOW_INFORMATION.fullmatch(cleaned):
        return "报文测速诊断" if has_capture else None
    for _ in range(3):
        shortened = _TITLE_PREFIX.sub("", cleaned).strip(" ，,：:。.!！?？")
        if shortened == cleaned:
            break
        cleaned = shortened
    cleaned = cleaned.replace("<本地路径已隐藏>", "报文文件")
    cleaned = cleaned.replace("<敏感信息已隐藏>", "")
    cleaned = re.split(r"[\n。！？!?；;]", cleaned, maxsplit=1)[0]
    cleaned = cleaned.strip(" ，,：:。.!！?？-_")
    if not cleaned or _LOW_INFORMATION.fullmatch(cleaned):
        return "报文测速诊断" if has_capture else None
    if has_capture and len(cleaned) < 4:
        return "报文测速诊断"
    return cleaned if len(cleaned) <= 28 else cleaned[:27].rstrip() + "…"


def _redact(value: str) -> str:
    # Web 数据库和 API 消息不能保留 API Key 或绝对本地路径。
    without_secrets = _SECRET.sub("<敏感信息已隐藏>", value)
    return _ABSOLUTE_PATH.sub("<本地路径已隐藏>", without_secrets)


redact_message = _redact


def _not_ready(message: str) -> AppError:
    return AppError(
        code="ANALYSIS_NOT_READY",
        message=message,
        recoverable=True,
        suggested_action="请补充并确认报文、标准带宽和实际带宽。",
    )


def _not_found(code: str, message: str) -> AppError:
    return AppError(
        code=code,
        message=message,
        recoverable=True,
        suggested_action="请刷新页面后重试。",
    )
