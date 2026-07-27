import socket
from pathlib import Path

from fastapi.testclient import TestClient

from packetmaster.config import Settings
from packetmaster.web.api import create_app
from packetmaster.web.runtime import find_available_port, static_directory


def test_port_selection_skips_an_occupied_loopback_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        port = int(occupied.getsockname()[1])

        selected = find_available_port("127.0.0.1", port, attempts=2)

    assert selected == port + 1


def test_production_app_serves_built_workspace_and_keeps_api_errors_json(
    tmp_path: Path,
) -> None:
    settings = Settings(
        web_database_path=tmp_path / "web.sqlite",
        web_allowed_capture_roots=[tmp_path],
    )
    client = TestClient(
        create_app(settings, testing=True, static_directory=static_directory())
    )

    index = client.get("/")
    missing_api = client.get("/api/does-not-exist")

    assert index.status_code == 200
    assert "PacketMaster" in index.text
    assert missing_api.status_code == 404
    assert missing_api.json()["error"]["code"] == "API_NOT_FOUND"
