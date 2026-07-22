from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from packetmaster.domain import CoverageSummary
from tests.helpers import load_script_module

store_module = load_script_module("lib/store.py", "speed_analyze_store")


def event(
    evidence_id: str,
    *,
    event_type: str = "retransmission",
    frame_number: int = 1,
    time_relative: float | None = 1.0,
    flow_id: str = "tcp|192.0.2.1:1|198.51.100.2:2",
    direction: str = "download",
    seq: int | None = 10,
) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "event_type": event_type,
        "frame.number": frame_number,
        "frame.time_relative": time_relative,
        "flow_id": flow_id,
        "direction": direction,
        "tcp.seq": seq,
        "tcp.ack": 20,
        "tcp.window_size": 65535,
        "tcp.len": 1000,
        "tcp.analysis.ack_rtt": 0.004,
    }


def result_fixture() -> SimpleNamespace:
    return SimpleNamespace(
        coverage_summary=CoverageSummary(
            total_packets_seen=3,
            tcp_packets_seen=3,
            speed_packets_analyzed=3,
            analyzed_bytes=1750,
            analyzed_duration_seconds=1.75,
        ),
        tcp_summary={"flow_count": 2, "note": "链路"},
        flows={
            "flow-one": {"packet_count": 2, "payload_bytes": 1500},
            "流-二": {"packet_count": 1, "payload_bytes": 250},
        },
        intervals=[
            {
                "interval_start": 0.0,
                "interval_end": 1.0,
                "direction": "download",
                "packet_count": 2,
                "payload_bytes": 1500,
            }
        ],
        syn_options={"mss_values": {"1460": 1}, "label": "支持"},
        events=[],
    )


def table_names(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    return {row[0] for row in rows}


def test_initialize_and_write_result_replace_summary_tables(tmp_path: Path) -> None:
    path = tmp_path / "evidence.sqlite"
    store = store_module.AnalysisStore(path)
    store.initialize()

    store.write_result(result_fixture())
    store.write_result(result_fixture())

    assert table_names(path) >= {
        "summary",
        "flows",
        "intervals",
        "events",
        "syn_options",
    }
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM summary").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM intervals").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM syn_options").fetchone()[0] == 1
    store.close()


def test_append_event_flushes_at_batch_size_and_close_flushes_tail(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.sqlite"
    store = store_module.AnalysisStore(path, event_batch_size=2)
    store.initialize()

    store.append_event(event("e1"))
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0

    store.append_event(event("e2", frame_number=2))
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2

    store.append_event(event("e3", frame_number=3))
    store.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3


def test_duplicate_evidence_id_raises_and_preserves_committed_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate-events.sqlite"
    store = store_module.AnalysisStore(path)
    store.initialize()
    store.append_event(event("duplicate", event_type="retransmission"))
    store.flush_events()
    store.append_event(event("duplicate", event_type="zero_window"))

    with pytest.raises(sqlite3.IntegrityError):
        store.flush_events()

    assert store._event_buffer
    with sqlite3.connect(path) as connection:
        stored_event_type = connection.execute(
            "SELECT event_type FROM events WHERE evidence_id = ?", ("duplicate",)
        ).fetchone()[0]
    assert stored_event_type == "retransmission"
    store._event_buffer.clear()
    store.close()


def test_context_manager_closes_store_and_rejects_further_operations(
    tmp_path: Path,
) -> None:
    with store_module.AnalysisStore(tmp_path / "context.sqlite") as store:
        store.initialize()
        store.append_event(event("e1"))

    with pytest.raises(RuntimeError, match="closed"):
        store.query_events()
    with pytest.raises(RuntimeError, match="closed"):
        store.append_event(event("e2"))


def test_unicode_path_and_json_are_preserved_without_ascii_escaping(
    tmp_path: Path,
) -> None:
    path = tmp_path / "分析 证据.sqlite"
    with store_module.AnalysisStore(path) as store:
        store.initialize()
        store.write_result(result_fixture())

    with sqlite3.connect(path) as connection:
        summary_json = connection.execute(
            "SELECT value_json FROM summary WHERE name = 'tcp_summary'"
        ).fetchone()[0]
        flow_json = connection.execute(
            "SELECT data_json FROM flows WHERE flow_id = '流-二'"
        ).fetchone()[0]
    assert "链路" in summary_json
    assert "流-二" not in flow_json
    assert "\\u94fe" not in summary_json


def populated_store(path: Path) -> object:
    store = store_module.AnalysisStore(path, event_batch_size=50)
    store.initialize()
    store.append_event(event("late", frame_number=9, time_relative=5.0))
    store.append_event(
        event(
            "first",
            event_type="duplicate_ack",
            frame_number=1,
            time_relative=1.0,
            flow_id="flow-a",
            seq=None,
        )
    )
    store.append_event(
        event(
            "second",
            event_type="zero_window",
            frame_number=2,
            time_relative=1.0,
            flow_id="flow-b",
        )
    )
    store.append_event(
        event(
            "third",
            event_type="duplicate_ack",
            frame_number=3,
            time_relative=2.0,
            flow_id="flow-a",
        )
    )
    store.flush_events()
    return store


def test_query_custom_returns_requested_aliases_with_stable_pagination(
    tmp_path: Path,
) -> None:
    store = populated_store(tmp_path / "query.sqlite")

    page = store.query_custom(
        fields=["evidence_id", "frame.number", "frame.time_relative"],
        predicates=[],
        offset=1,
        limit=2,
    )

    assert page == [
        {"evidence_id": "second", "frame.number": 2, "frame.time_relative": 1.0},
        {"evidence_id": "third", "frame.number": 3, "frame.time_relative": 2.0},
    ]
    store.close()


@pytest.mark.parametrize("offset", [-1, 1.5, "0"])
def test_query_custom_rejects_invalid_offset(tmp_path: Path, offset: object) -> None:
    store = populated_store(tmp_path / f"offset-{offset}.sqlite")
    with pytest.raises((TypeError, ValueError)):
        store.query_custom(["evidence_id"], [], offset=offset, limit=1)
    store.close()


@pytest.mark.parametrize("limit", [0, 501, 1.5, "100"])
def test_queries_reject_invalid_limit(tmp_path: Path, limit: object) -> None:
    store = populated_store(tmp_path / f"limit-{limit}.sqlite")
    with pytest.raises((TypeError, ValueError)):
        store.query_custom(["evidence_id"], [], offset=0, limit=limit)
    with pytest.raises((TypeError, ValueError)):
        store.query_events(limit=limit)
    store.close()


@pytest.mark.parametrize(
    ("fields", "predicates"),
    [
        (["not_a_field"], []),
        (["evidence_id"], [{"field": "not_a_field", "operator": "eq", "value": 1}]),
        (["evidence_id"], [{"field": "event_type", "operator": "LIKE", "value": "%"}]),
        (["evidence_id"], [{"field": "event_type", "operator": "in", "value": []}]),
        (
            ["evidence_id"],
            [
                {
                    "field": "event_type",
                    "operator": "in",
                    "value": ("duplicate_ack",),
                }
            ],
        ),
        (
            ["evidence_id"],
            [{"field": "tcp.seq", "operator": "exists", "value": 0}],
        ),
    ],
)
def test_query_custom_enforces_field_and_operator_whitelists(
    tmp_path: Path,
    fields: list[str],
    predicates: list[dict[str, object]],
) -> None:
    store = populated_store(tmp_path / "whitelist.sqlite")
    with pytest.raises(ValueError):
        store.query_custom(fields, predicates, offset=0, limit=10)
    store.close()


def test_query_custom_rejects_string_flow_ids(tmp_path: Path) -> None:
    store = populated_store(tmp_path / "flow-ids.sqlite")
    with pytest.raises(ValueError, match="flow_ids"):
        store.query_custom(
            ["evidence_id"], [], offset=0, limit=10, flow_ids=""
        )
    store.close()


def test_query_custom_supports_in_exists_and_parameterized_injection_values(
    tmp_path: Path,
) -> None:
    store = populated_store(tmp_path / "safe.sqlite")
    injection = "retransmission' OR 1=1 --"
    store.append_event(
        event(
            "injection",
            event_type=injection,
            frame_number=20,
            time_relative=20.0,
        )
    )
    store.flush_events()

    selected = store.query_custom(
        ["evidence_id", "event_type"],
        [
            {
                "field": "event_type",
                "operator": "in",
                "value": ["duplicate_ack", injection],
            },
            {"field": "tcp.seq", "operator": "exists", "value": True},
        ],
        offset=0,
        limit=10,
    )
    missing_seq = store.query_custom(
        ["evidence_id"],
        [{"field": "tcp.seq", "operator": "exists", "value": False}],
        offset=0,
        limit=10,
    )

    assert [item["evidence_id"] for item in selected] == ["third", "injection"]
    assert missing_seq == [{"evidence_id": "first"}]
    assert store.query_events()["total"] == 5
    store.close()


def test_flow_and_time_filters_apply_to_custom_and_predefined_queries(
    tmp_path: Path,
) -> None:
    store = populated_store(tmp_path / "filters.sqlite")

    custom = store.query_custom(
        ["evidence_id", "flow_id"],
        [],
        offset=0,
        limit=10,
        flow_ids=["flow-a"],
        time_start=1.5,
        time_end=3.0,
    )
    predefined = store.query_events(
        event_type="duplicate_ack",
        flow_id="flow-a",
        time_start=0.0,
        time_end=2.0,
        offset=0,
        limit=1,
    )

    assert custom == [{"evidence_id": "third", "flow_id": "flow-a"}]
    assert predefined["items"][0]["evidence_id"] == "first"
    assert predefined["total"] == 2
    assert predefined["next_offset"] == 1
    second_page = store.query_events(
        event_type="duplicate_ack",
        flow_id="flow-a",
        time_start=0.0,
        time_end=2.0,
        offset=1,
        limit=1,
    )
    assert second_page["items"][0]["evidence_id"] == "third"
    assert second_page["next_offset"] is None
    store.close()
