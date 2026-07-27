from pathlib import Path

from fastapi.testclient import TestClient

from packetmaster.config import Settings
from packetmaster.web.api import create_app


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        web_database_path=tmp_path / "web.sqlite",
        model_api_key="test-key",
        tshark_path="definitely-not-installed-tshark",
        web_allowed_capture_roots=[tmp_path],
    )
    return TestClient(create_app(settings, testing=True))


def test_health_uses_public_configuration_flags_and_security_headers(
    tmp_path: Path,
) -> None:
    response = _client(tmp_path).get(
        "/api/health", headers={"X-Request-ID": "request-1"}
    )

    assert response.status_code == 200
    assert response.json()["data"]["model_configured"] is True
    assert response.json()["data"]["tshark_configured"] is False
    assert "test-key" not in response.text
    assert response.headers["x-request-id"] == "request-1"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_corrupt_rag_database_does_not_block_web_startup(tmp_path: Path) -> None:
    knowledge_path = tmp_path / "knowledge.sqlite"
    knowledge_path.write_bytes(b"corrupt knowledge database")
    settings = Settings(
        web_database_path=tmp_path / "web.sqlite",
        knowledge_database_path=knowledge_path,
        rag_enabled=True,
        rag_mode="shadow",
        tshark_path="definitely-not-installed-tshark",
        web_allowed_capture_roots=[tmp_path],
    )

    with TestClient(create_app(settings, testing=True)) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "ok"


def test_non_local_host_and_origin_are_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)

    host = client.get("/api/health", headers={"Host": "example.com"})
    origin = client.get(
        "/api/health", headers={"Origin": "https://example.com"}
    )

    assert host.status_code == 403
    assert host.json()["error"]["code"] == "HOST_NOT_ALLOWED"
    assert origin.status_code == 403
    assert origin.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"


def test_unknown_api_uses_stable_error_envelope(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/api/missing")

    assert response.status_code == 404
    assert response.json()["ok"] is False
    assert response.json()["error"]["code"] == "API_NOT_FOUND"
    assert "traceback" not in response.text.casefold()


def test_session_capture_message_and_confirmation_api(tmp_path: Path) -> None:
    client = _client(tmp_path)
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    session = client.post("/api/sessions", json={"title": "测速诊断"}).json()["data"]
    capture = client.post(
        "/api/captures/register", json={"path": str(capture_path)}
    ).json()["data"]

    message = client.post(
        f"/api/sessions/{session['session_id']}/messages",
        json={
            "content": "标准带宽1G，实际带宽20M",
            "capture_id": capture["capture_id"],
        },
    )
    confirmed = client.post(
        f"/api/sessions/{session['session_id']}/confirm", json={}
    )
    repeated = client.post(
        f"/api/sessions/{session['session_id']}/confirm", json={}
    )
    detail = client.get(f"/api/sessions/{session['session_id']}")

    assert message.status_code == 200
    assert message.json()["data"]["parameters"]["ready_for_confirmation"] is True
    assert message.json()["data"]["parameters"]["target"] == "download"
    assert confirmed.status_code == 200
    assert (
        repeated.json()["data"]["analysis_id"]
        == confirmed.json()["data"]["analysis_id"]
    )
    assert detail.json()["data"]["messages"]["total"] == 3
    combined = message.text + confirmed.text + detail.text
    assert str(capture_path) not in combined
    assert "test-key" not in combined


def test_session_and_capture_listing_and_deletion_api(tmp_path: Path) -> None:
    client = _client(tmp_path)
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(b"capture")
    session = client.post("/api/sessions", json={}).json()["data"]
    capture = client.post(
        "/api/captures/register", json={"path": str(capture_path)}
    ).json()["data"]

    assert client.get("/api/sessions").json()["data"]["total"] == 1
    assert client.get("/api/captures/recent").json()["data"][0] == capture
    assert client.delete(f"/api/captures/{capture['capture_id']}").status_code == 200
    assert capture_path.is_file()
    assert client.delete(f"/api/sessions/{session['session_id']}").status_code == 200
