from pathlib import Path

from fastapi.testclient import TestClient

from packetmaster.config import Settings
from packetmaster.web.api import create_app


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        web_database_path=tmp_path / "web.sqlite",
        model_api_key="test-key",
        tshark_path="definitely-not-installed-tshark",
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
