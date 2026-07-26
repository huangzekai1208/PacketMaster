from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packetmaster.web.contracts import (
    AnalysisEvent,
    ApiError,
    CaptureSummary,
    DiagnosisParameters,
    ErrorEnvelope,
    EventType,
    MissingParameter,
    TaskStatus,
    public_json,
)


def test_public_capture_only_accepts_a_file_name() -> None:
    capture = CaptureSummary(
        capture_id="capture-1", file_name="测速报文.pcapng", size_bytes=1024
    )

    assert public_json(capture) == {
        "capture_id": "capture-1",
        "file_name": "测速报文.pcapng",
        "size_bytes": 1024,
    }
    with pytest.raises(ValidationError):
        CaptureSummary(
            capture_id="capture-2",
            file_name="/Users/me/secret.pcapng",
            size_bytes=1,
        )
    with pytest.raises(ValidationError):
        CaptureSummary(
            capture_id="capture-3",
            file_name=r"C:\captures\secret.pcapng",
            size_bytes=1,
        )


def test_diagnosis_parameters_use_public_missing_names_and_download_default() -> None:
    parameters = DiagnosisParameters(
        missing=[
            MissingParameter.CAPTURE,
            MissingParameter.STANDARD_BANDWIDTH,
        ]
    )

    assert parameters.target.value == "download"
    assert public_json(parameters)["missing"] == [
        "capture",
        "standard_bandwidth",
    ]
    assert "standard_bandwidth_mbps" not in public_json(parameters)["missing"]


def test_analysis_event_rejects_invalid_progress_and_extra_sensitive_fields() -> None:
    now = datetime.now(UTC)
    event = AnalysisEvent(
        event_id=1,
        analysis_id="analysis-1",
        event_type=EventType.ANALYSIS_PROGRESS,
        status=TaskStatus.ANALYZING,
        created_at=now,
        progress_fraction=0.5,
    )

    assert public_json(event)["progress_fraction"] == 0.5
    with pytest.raises(ValidationError):
        AnalysisEvent(
            event_id=2,
            analysis_id="analysis-1",
            event_type=EventType.ANALYSIS_PROGRESS,
            status=TaskStatus.ANALYZING,
            created_at=now,
            progress_fraction=2,
        )
    with pytest.raises(ValidationError):
        AnalysisEvent(
            event_id=3,
            analysis_id="analysis-1",
            event_type=EventType.ANALYSIS_PROGRESS,
            status=TaskStatus.ANALYZING,
            created_at=now,
            api_key="secret",
        )


def test_error_envelope_has_stable_public_shape() -> None:
    envelope = ErrorEnvelope(
        error=ApiError(
            code="CAPTURE_NOT_FOUND",
            message="报文文件不存在",
            recoverable=True,
            suggested_action="重新注册报文文件。",
        ),
        request_id="request-1",
    )

    assert public_json(envelope) == {
        "ok": False,
        "error": {
            "code": "CAPTURE_NOT_FOUND",
            "message": "报文文件不存在",
            "recoverable": True,
            "suggested_action": "重新注册报文文件。",
            "details": {},
        },
        "request_id": "request-1",
    }
