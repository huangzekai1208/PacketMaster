from packetmaster.domain import DiagnosisIntent, Target
from packetmaster.intent import (
    PathRegistry,
    extract_capture_paths,
    merge_intent,
    normalize_bandwidth,
)


def test_extracts_unicode_windows_path_with_spaces_and_hides_it() -> None:
    text = '分析 "C:\\captures\\测速 报文.pcapng"，标准 1Gbps，实际 600M'
    extracted = extract_capture_paths(text)

    assert len(extracted.references) == 1
    assert extracted.references[0].placeholder in extracted.sanitized_text
    assert "C:\\captures" not in extracted.sanitized_text
    assert extracted.registry.resolve(extracted.references[0]).endswith(
        "测速 报文.pcapng"
    )


def test_extracts_posix_relative_and_bare_paths() -> None:
    extracted = extract_capture_paths(
        "分析 ./captures/test.pcap 和 /tmp/另一个.pcapng"
    )

    assert len(extracted.references) == 2
    assert all(".pcap" not in extracted.sanitized_text for _ in extracted.references)


def test_multiple_paths_are_kept_local_and_distinct() -> None:
    extracted = extract_capture_paths("a.pcap 与 b.pcap")

    assert len(extracted.references) == 2
    assert len(extracted.registry.values()) == 2


def test_normalizes_common_bandwidth_units() -> None:
    assert normalize_bandwidth(1, "Gbps") == 1000
    assert normalize_bandwidth(600, "M") == 600
    assert normalize_bandwidth(800, "兆") == 800


def test_merge_defaults_to_download_and_tracks_missing_fields() -> None:
    intent = merge_intent(
        None,
        DiagnosisIntent(
            standard_bandwidth_value=1,
            standard_bandwidth_unit="G",
            actual_bandwidth_value=600,
            actual_bandwidth_unit="M",
        ),
    )

    assert intent.target is Target.DOWNLOAD
    assert intent.standard_bandwidth_mbps == 1000
    assert intent.actual_bandwidth_mbps == 600
    assert intent.missing_fields == ["capture"]
    assert intent.confirmed is False


def test_complete_intent_still_requires_explicit_confirmation() -> None:
    extracted = extract_capture_paths("分析 ./captures/test.pcapng")
    intent = merge_intent(
        None,
        DiagnosisIntent(
            capture=extracted.references[0],
            standard_bandwidth_value=1,
            standard_bandwidth_unit="G",
            actual_bandwidth_value=600,
            actual_bandwidth_unit="M",
        ),
    )

    assert intent.missing_fields == []
    assert intent.ambiguities == []
    assert intent.confirmed is False


def test_path_registry_rejects_unknown_reference() -> None:
    registry = PathRegistry()
    extracted = extract_capture_paths("test.pcap")
    assert extracted.references
    try:
        registry.resolve(extracted.references[0])
    except ValueError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("unknown path reference should be rejected")


def test_path_registry_keeps_prior_turn_references() -> None:
    first = extract_capture_paths("分析 ./captures/test.pcapng")
    correction = extract_capture_paths("实际带宽改为 580M")

    first.registry.extend(correction.registry)

    assert first.registry.resolve(first.references[0]).endswith("test.pcapng")
