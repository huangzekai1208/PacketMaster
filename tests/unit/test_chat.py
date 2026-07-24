import pytest
from pydantic import ValidationError

from packetmaster.artifacts import ArtifactManager
from packetmaster.chat import (
    ChatCommand,
    ChatSession,
    ConversationRoute,
    build_model_context,
    parse_command,
    route_conversation,
    validate_question,
)
from packetmaster.domain import (
    ChatAnswer,
    ChatEvidenceCitation,
    ChatSessionState,
    DiagnosisIntent,
    PathReference,
    Target,
)
from packetmaster.report import render_chat_report


def test_chat_answer_rejects_empty_question_like_answer() -> None:
    with pytest.raises(ValidationError):
        ChatAnswer(answer="", ready=False)


def test_chat_question_validation_rejects_empty_and_long_values() -> None:
    with pytest.raises(ValueError):
        validate_question("  ")
    with pytest.raises(ValueError):
        validate_question("x" * 2_001)


def test_chat_answer_rejects_more_than_five_evidence_requests() -> None:
    request = {
        "analysis_id": "analysis-1",
        "evidence_type": "summary",
    }
    with pytest.raises(ValidationError):
        ChatAnswer(
            answer="需要更多证据",
            requested_evidence=[request] * 6,
        )


def test_model_context_hides_local_path_payload_and_key() -> None:
    state = ChatSessionState(
        session_id="session-1",
        analysis_id="analysis-1",
        target=Target.DOWNLOAD,
        question="主因是什么？",
        report={
            "analysis_metadata": {
                "pcap_path": "/Users/me/captures/test.pcapng",
                "api_key": "secret",
            },
            "coverage_summary": {"complete": True},
        },
        collected_evidence=[
            {"payload": "sensitive", "frame.number": 12},
        ],
    )

    context = build_model_context(state).model_dump(mode="json")
    serialized = str(context)
    assert "/Users/me" not in serialized
    assert "secret" not in serialized
    assert "sensitive" not in serialized
    assert context["analysis_id"] == "analysis-1"


def test_model_context_rejects_cross_task_question_state() -> None:
    state = ChatSessionState(session_id="session-1", question="证据？")
    with pytest.raises(ValueError, match="analysis_id"):
        build_model_context(state)


def test_chat_models_reject_extra_fields_and_invalid_citation() -> None:
    with pytest.raises(ValidationError):
        DiagnosisIntent(extra="nope")
    with pytest.raises(ValidationError):
        PathReference(placeholder="/Users/me/test.pcapng")
    with pytest.raises(ValidationError):
        ChatEvidenceCitation(analysis_id="a", evidence_type="e", frame_number=-1)


def test_slash_commands_are_deterministic_and_case_insensitive() -> None:
    assert parse_command("/REPORT").command is ChatCommand.REPORT
    assert parse_command("/evidence flow-1").argument == "flow-1"
    assert parse_command("/unknown").command is ChatCommand.UNKNOWN
    assert parse_command("  ").command is ChatCommand.EMPTY
    assert parse_command("主因是什么？") is None


def test_conversation_router_separates_general_and_diagnosis_turns() -> None:
    assert route_conversation(
        "TCP 是什么？", has_analysis=False, has_pending_intent=False
    ) is ConversationRoute.GENERAL
    assert route_conversation(
        "帮我分析测速不达标原因", has_analysis=False, has_pending_intent=False
    ) is ConversationRoute.DIAGNOSIS
    assert route_conversation(
        "1000", has_analysis=False, has_pending_intent=True
    ) is ConversationRoute.DIAGNOSIS
    assert route_conversation(
        "主要原因是什么？", has_analysis=True, has_pending_intent=False
    ) is ConversationRoute.ANALYSIS_QUESTION
    assert route_conversation(
        "你好", has_analysis=True, has_pending_intent=False
    ) is ConversationRoute.GENERAL


def test_chat_session_archives_old_turns_with_byte_bound() -> None:
    session = ChatSession(ChatSessionState(session_id="session-1"))
    for index in range(10):
        session.append_turn(f"问题 {index}", "回答" * 1000)

    assert len(session.state.conversation_turns) == 8
    assert len(session.state.conversation_summary.encode("utf-8")) <= 8_000


def test_chat_session_active_artifact_is_removed_on_finish(tmp_path) -> None:
    manager = ArtifactManager(tmp_path / "artifacts", ttl_hours=24)
    session = ChatSession(ChatSessionState(session_id="session-1"), manager)
    paths = session.attach_analysis("analysis-1")
    assert paths is not None
    assert (paths.root / ".active").exists()
    session.finish()
    assert not (paths.root / ".active").exists()


def test_chat_report_renders_all_candidates_without_model_call() -> None:
    from packetmaster.domain import CoverageSummary, DiagnosticReport, Hypothesis

    report = DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
        achievement_ratio_pct=60,
        confidence=70,
        coverage_summary=CoverageSummary(complete=True),
        candidate_causes=[
            Hypothesis(
                cause="重传",
                hypothesis_type="known_pattern",
                observability="direct",
                confidence=70,
                supporting_evidence=["ev-1"],
                suggestion="检查链路丢包",
            )
        ],
        key_evidence=[
            {
                "evidence_type": "retransmission",
                "total": 1,
                "references": [{"frame.number": 42, "flow_id": "flow-1"}],
            }
        ],
        limitations=["抓包时长较短"],
        troubleshooting_steps=["检查链路丢包"],
        optimization_suggestions=["延长测速时间"],
    )
    output = render_chat_report(report)
    assert "候选原因" in output
    assert "重传" in output
    assert "70.00%" in output
    assert "frame.number=42" in output
    assert "抓包时长较短" in output
    assert "延长测速时间" in output
