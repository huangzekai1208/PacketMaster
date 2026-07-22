from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

FIELD_COLUMNS = {
    "evidence_id": "evidence_id",
    "event_type": "event_type",
    "frame.number": "frame_number",
    "frame.time_relative": "time_relative",
    "flow_id": "flow_id",
    "direction": "direction",
    "tcp.seq": "tcp_seq",
    "tcp.ack": "tcp_ack",
    "tcp.window_size": "tcp_window_size",
    "tcp.len": "tcp_len",
    "tcp.analysis.ack_rtt": "ack_rtt",
}
OPERATOR_SQL = {
    "eq": "=",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}
EVENT_INSERT_SQL = """
    INSERT INTO events (
        evidence_id, event_type, frame_number, time_relative, flow_id, direction,
        tcp_seq, tcp_ack, tcp_window_size, tcp_len, ack_rtt
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
EVENT_SELECT_FIELDS = tuple(FIELD_COLUMNS)


def _paging(offset: int, limit: int) -> None:
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")


def _time_value(value: float | None, name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{name} must be a number")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{name} must be a finite non-negative number")
    return parsed


def _json_value(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _predicate_parts(predicate: object) -> tuple[str, str, Any]:
    if isinstance(predicate, Mapping):
        try:
            field = predicate["field"]
            operator = predicate["operator"]
        except KeyError as exc:
            raise ValueError("predicate requires field and operator") from exc
        value = predicate.get("value")
    else:
        try:
            field = getattr(predicate, "field")
            operator = getattr(predicate, "operator")
        except AttributeError as exc:
            raise ValueError("predicate requires field and operator") from exc
        value = getattr(predicate, "value", None)
    if hasattr(field, "value"):
        field = field.value
    if hasattr(operator, "value"):
        operator = operator.value
    if not isinstance(field, str) or not isinstance(operator, str):
        raise ValueError("predicate field and operator must be strings")
    return field, operator, value


class AnalysisStore:
    def __init__(self, path: Path, event_batch_size: int = 500) -> None:
        if isinstance(event_batch_size, bool) or not isinstance(event_batch_size, int):
            raise TypeError("event_batch_size must be an integer")
        if event_batch_size < 1:
            raise ValueError("event_batch_size must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.event_batch_size = event_batch_size
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._event_buffer: list[tuple[Any, ...]] = []
        self._closed = False

    def __enter__(self) -> AnalysisStore:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("AnalysisStore is closed")

    def initialize(self) -> None:
        self._ensure_open()
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS summary (
                name TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS flows (
                flow_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intervals (
                interval_start REAL NOT NULL,
                direction TEXT NOT NULL,
                data_json TEXT NOT NULL,
                PRIMARY KEY (interval_start, direction)
            );
            CREATE TABLE IF NOT EXISTS events (
                evidence_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                frame_number INTEGER,
                time_relative REAL,
                flow_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                tcp_seq INTEGER,
                tcp_ack INTEGER,
                tcp_window_size INTEGER,
                tcp_len INTEGER,
                ack_rtt REAL
            );
            CREATE TABLE IF NOT EXISTS syn_options (
                name TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_type_time
                ON events (event_type, time_relative, frame_number, evidence_id);
            CREATE INDEX IF NOT EXISTS idx_events_flow_time
                ON events (flow_id, time_relative, frame_number, evidence_id);
            CREATE INDEX IF NOT EXISTS idx_events_time
                ON events (time_relative, frame_number, evidence_id);
            """
        )
        self._connection.commit()

    def append_event(self, event: Mapping[str, Any]) -> None:
        self._ensure_open()
        try:
            values = (
                event["evidence_id"],
                event["event_type"],
                event.get("frame.number"),
                event.get("frame.time_relative"),
                event["flow_id"],
                event["direction"],
                event.get("tcp.seq"),
                event.get("tcp.ack"),
                event.get("tcp.window_size"),
                event.get("tcp.len"),
                event.get("tcp.analysis.ack_rtt"),
            )
        except KeyError as exc:
            raise ValueError(f"event is missing required field: {exc.args[0]}") from exc
        self._event_buffer.append(values)
        if len(self._event_buffer) >= self.event_batch_size:
            self.flush_events()

    def flush_events(self) -> None:
        self._ensure_open()
        if not self._event_buffer:
            return
        try:
            self._connection.executemany(EVENT_INSERT_SQL, self._event_buffer)
            self._connection.commit()
        except sqlite3.Error:
            self._connection.rollback()
            raise
        else:
            self._event_buffer.clear()

    def write_result(self, result: object) -> None:
        self._ensure_open()
        self.flush_events()
        coverage = getattr(result, "coverage_summary")
        tcp_summary = getattr(result, "tcp_summary")
        flows = getattr(result, "flows")
        intervals = getattr(result, "intervals")
        syn_options = getattr(result, "syn_options")

        with self._connection:
            self._connection.executemany(
                "INSERT OR REPLACE INTO summary (name, value_json) VALUES (?, ?)",
                (
                    ("coverage_summary", _json_value(coverage)),
                    ("tcp_summary", _json_value(tcp_summary)),
                ),
            )
            self._connection.execute("DELETE FROM flows")
            self._connection.executemany(
                "INSERT INTO flows (flow_id, data_json) VALUES (?, ?)",
                ((flow_id, _json_value(data)) for flow_id, data in flows.items()),
            )
            self._connection.execute("DELETE FROM intervals")
            self._connection.executemany(
                """
                INSERT INTO intervals (interval_start, direction, data_json)
                VALUES (?, ?, ?)
                """,
                (
                    (
                        interval["interval_start"],
                        interval["direction"],
                        _json_value(interval),
                    )
                    for interval in intervals
                ),
            )
            self._connection.execute("DELETE FROM syn_options")
            self._connection.execute(
                "INSERT INTO syn_options (name, value_json) VALUES (?, ?)",
                ("syn_options", _json_value(syn_options)),
            )

    def _where_clause(
        self,
        predicates: Sequence[object],
        flow_ids: Sequence[str] | None,
        time_start: float | None,
        time_end: float | None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for predicate in predicates:
            field, operator, value = _predicate_parts(predicate)
            try:
                column = FIELD_COLUMNS[field]
            except KeyError as exc:
                raise ValueError(f"unsupported query field: {field}") from exc
            if operator in OPERATOR_SQL:
                clauses.append(f"{column} {OPERATOR_SQL[operator]} ?")
                parameters.append(value)
            elif operator == "in":
                if not isinstance(value, list):
                    raise ValueError("in predicate value must be a non-empty list")
                if not value:
                    raise ValueError("in predicate value must be a non-empty list")
                placeholders = ", ".join("?" for _ in value)
                clauses.append(f"{column} IN ({placeholders})")
                parameters.extend(value)
            elif operator == "exists":
                if value is not None and not isinstance(value, bool):
                    raise ValueError("exists predicate value must be boolean")
                suffix = "NULL" if value is False else "NOT NULL"
                clauses.append(f"{column} IS {suffix}")
            else:
                raise ValueError(f"unsupported query operator: {operator}")

        if flow_ids is not None:
            if isinstance(flow_ids, str | bytes) or not isinstance(
                flow_ids, Sequence
            ) or not all(
                isinstance(flow_id, str) for flow_id in flow_ids
            ):
                raise ValueError("flow_ids must be a sequence of strings")
            if flow_ids:
                placeholders = ", ".join("?" for _ in flow_ids)
                clauses.append(f"flow_id IN ({placeholders})")
                parameters.extend(flow_ids)
        parsed_start = _time_value(time_start, "time_start")
        parsed_end = _time_value(time_end, "time_end")
        if parsed_start is not None and parsed_end is not None:
            if parsed_start > parsed_end:
                raise ValueError("time_start must not exceed time_end")
        if parsed_start is not None:
            clauses.append("time_relative >= ?")
            parameters.append(parsed_start)
        if parsed_end is not None:
            clauses.append("time_relative <= ?")
            parameters.append(parsed_end)
        return (" WHERE " + " AND ".join(clauses) if clauses else "", parameters)

    def query_custom(
        self,
        fields: Sequence[str],
        predicates: Sequence[object],
        offset: int,
        limit: int,
        flow_ids: Sequence[str] | None = None,
        time_start: float | None = None,
        time_end: float | None = None,
    ) -> list[dict[str, object]]:
        self._ensure_open()
        _paging(offset, limit)
        if not fields:
            raise ValueError("at least one query field is required")
        if len(set(fields)) != len(fields):
            raise ValueError("query fields must be unique")
        try:
            selections = [f'{FIELD_COLUMNS[field]} AS "{field}"' for field in fields]
        except KeyError as exc:
            raise ValueError(f"unsupported query field: {exc.args[0]}") from exc
        where_sql, parameters = self._where_clause(
            predicates, flow_ids, time_start, time_end
        )
        sql = (
            f"SELECT {', '.join(selections)} FROM events{where_sql} "
            "ORDER BY time_relative IS NULL, time_relative, "
            "frame_number IS NULL, frame_number, evidence_id LIMIT ? OFFSET ?"
        )
        rows = self._connection.execute(
            sql, [*parameters, limit, offset]
        ).fetchall()
        return [dict(row) for row in rows]

    def query_events(
        self,
        event_type: str | None = None,
        flow_id: str | None = None,
        time_start: float | None = None,
        time_end: float | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, object]:
        self._ensure_open()
        _paging(offset, limit)
        predicates: list[dict[str, object]] = []
        if event_type is not None:
            predicates.append(
                {"field": "event_type", "operator": "eq", "value": event_type}
            )
        flow_ids = [flow_id] if flow_id is not None else None
        where_sql, parameters = self._where_clause(
            predicates, flow_ids, time_start, time_end
        )
        total = self._connection.execute(
            f"SELECT COUNT(*) FROM events{where_sql}", parameters
        ).fetchone()[0]
        items = self.query_custom(
            EVENT_SELECT_FIELDS,
            predicates,
            offset,
            limit,
            flow_ids=flow_ids,
            time_start=time_start,
            time_end=time_end,
        )
        next_offset = offset + len(items)
        if next_offset >= total:
            next_offset = None
        return {"items": items, "total": total, "next_offset": next_offset}

    def close(self) -> None:
        if self._closed:
            return
        self.flush_events()
        self._connection.close()
        self._closed = True
