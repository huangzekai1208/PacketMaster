from pathlib import Path

import pytest

from packetmaster.errors import AppError
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.database import WebDatabase


def _registry(tmp_path: Path, allowed: Path) -> CaptureRegistry:
    database = WebDatabase(tmp_path / "web.sqlite")
    database.initialize()
    return CaptureRegistry(
        CaptureRepository(database), allowed_roots=[allowed]
    )


def test_capture_registration_returns_only_public_metadata_and_reuses_id(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "允许目录"
    allowed.mkdir()
    capture = allowed / "测速 报文.pcapng"
    capture.write_bytes(b"pcapng")
    registry = _registry(tmp_path, allowed)

    first = registry.register(str(capture))
    second = registry.register(str(capture))

    assert first.capture_id == second.capture_id
    assert first.file_name == "测速 报文.pcapng"
    assert first.size_bytes == 6
    assert str(capture) not in str(first.model_dump(mode="json"))
    assert registry.resolve(first.capture_id) == capture.resolve()


def test_capture_registration_rejects_outside_root_and_invalid_inputs(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"capture")
    invalid = allowed / "capture.txt"
    invalid.write_text("not capture", encoding="utf-8")
    registry = _registry(tmp_path, allowed)

    with pytest.raises(AppError) as outside_error:
        registry.register(str(outside))
    assert outside_error.value.code == "CAPTURE_OUTSIDE_ALLOWED_ROOT"
    assert str(outside) not in str(outside_error.value.to_dict())

    with pytest.raises(AppError) as invalid_error:
        registry.register(str(invalid))
    assert invalid_error.value.code == "UNSUPPORTED_CAPTURE_TYPE"

    with pytest.raises(AppError) as relative_error:
        registry.register("capture.pcapng")
    assert relative_error.value.code == "CAPTURE_PATH_NOT_ABSOLUTE"


def test_capture_registration_rejects_symlink_escape(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.pcapng"
    outside.write_bytes(b"capture")
    link = allowed / "linked.pcapng"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    registry = _registry(tmp_path, allowed)

    with pytest.raises(AppError) as raised:
        registry.register(str(link))

    assert raised.value.code == "CAPTURE_OUTSIDE_ALLOWED_ROOT"


def test_deleting_capture_reference_never_deletes_original_file(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    capture = allowed / "capture.pcap"
    capture.write_bytes(b"capture")
    registry = _registry(tmp_path, allowed)
    registered = registry.register(str(capture))

    assert registry.delete(registered.capture_id) is True
    assert capture.is_file()
    with pytest.raises(AppError) as raised:
        registry.resolve(registered.capture_id)
    assert raised.value.code == "CAPTURE_REFERENCE_NOT_FOUND"
