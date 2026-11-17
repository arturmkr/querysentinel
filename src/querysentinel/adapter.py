from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row


@dataclass(frozen=True)
class QueryCounter:
    target_id: str
    dbid: int
    userid: int
    queryid: int
    toplevel: bool
    query_text: str
    calls: int
    total_exec_time_ms: float
    rows: int
    shared_blks_hit: int
    shared_blks_read: int
    temp_blks_read: int
    temp_blks_written: int
    stats_reset: datetime | None
    dealloc: int | None
    username: str | None = None

    @property
    def fingerprint(self) -> str:
        identity = f"{self.target_id}:{self.dbid}:{self.userid}:{self.queryid}:{int(self.toplevel)}"
        return hashlib.sha256(identity.encode()).hexdigest()


class DatabaseAdapter(ABC):
    @abstractmethod
    def collect_query_counters(self) -> list[QueryCounter]: ...

    @abstractmethod
    def get_table_metadata(self, table_names: list[str]) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_indexes(self, table_names: list[str]) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_table_statistics(self, table_names: list[str]) -> list[dict[str, Any]]: ...


class PostgreSQLAdapter(DatabaseAdapter):
    def __init__(
        self,
        target_id: str,
        dsn: str,
        statement_timeout_ms: int = 10_000,
        lock_timeout_ms: int = 2_000,
    ) -> None:
        self.target_id = target_id
        self.dsn = dsn
        self.options = (
            f"-c statement_timeout={statement_timeout_ms} "
            f"-c lock_timeout={lock_timeout_ms} "
            "-c idle_in_transaction_session_timeout=5000 "
            "-c application_name=querysentinel_collector"
        )

    def _connect(self):
        return psycopg.connect(
            self.dsn,
            autocommit=True,
            options=self.options,
            row_factory=dict_row,
        )

    def collect_query_counters(self) -> list[QueryCounter]:
        sql = """
            SELECT p.dbid, p.userid, p.queryid, p.toplevel, p.query,
                   p.calls, p.total_exec_time, p.rows,
                   p.shared_blks_hit, p.shared_blks_read,
                   p.temp_blks_read, p.temp_blks_written,
                   i.stats_reset, i.dealloc, pg_get_userbyid(p.userid) AS username
              FROM pg_stat_statements AS p
              CROSS JOIN pg_stat_statements_info AS i
             WHERE p.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
               AND p.userid <> (SELECT usesysid FROM pg_user WHERE usename = current_user)
               AND p.queryid IS NOT NULL
        """
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(sql)
            return [
                QueryCounter(
                    target_id=self.target_id,
                    dbid=row["dbid"],
                    userid=row["userid"],
                    queryid=row["queryid"],
                    toplevel=row["toplevel"],
                    query_text=row["query"][:20_000],
                    calls=row["calls"],
                    total_exec_time_ms=row["total_exec_time"],
                    rows=row["rows"],
                    shared_blks_hit=row["shared_blks_hit"],
                    shared_blks_read=row["shared_blks_read"],
                    temp_blks_read=row["temp_blks_read"],
                    temp_blks_written=row["temp_blks_written"],
                    stats_reset=row["stats_reset"],
                    dealloc=row["dealloc"],
                    username=row["username"],
                )
                for row in cursor.fetchall()
            ]

    def get_table_metadata(self, table_names: list[str]) -> list[dict[str, Any]]:
        if not table_names:
            return []
        sql = """
            SELECT n.nspname AS schema_name, c.relname AS table_name,
                   a.attname AS column_name, format_type(a.atttypid, a.atttypmod) AS data_type,
                   a.attnotnull AS not_null
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              JOIN pg_attribute a ON a.attrelid = c.oid
             WHERE c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
               AND c.relname = ANY(%s)
             ORDER BY n.nspname, c.relname, a.attnum
        """
        return self._rows(sql, (table_names,))

    def get_indexes(self, table_names: list[str]) -> list[dict[str, Any]]:
        if not table_names:
            return []
        sql = """
            SELECT schemaname AS schema_name, tablename AS table_name,
                   indexname AS index_name, indexdef AS definition
              FROM pg_indexes
             WHERE tablename = ANY(%s)
             ORDER BY schemaname, tablename, indexname
        """
        return self._rows(sql, (table_names,))

    def get_table_statistics(self, table_names: list[str]) -> list[dict[str, Any]]:
        if not table_names:
            return []
        sql = """
            SELECT schemaname AS schema_name, relname AS table_name,
                   n_live_tup, n_dead_tup, last_analyze, last_autoanalyze,
                   seq_scan, idx_scan
              FROM pg_stat_user_tables
             WHERE relname = ANY(%s)
             ORDER BY schemaname, relname
        """
        return self._rows(sql, (table_names,))

    def _rows(self, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_approved_explain(self, workload_id: str) -> dict[str, Any]:
        approved = APPROVED_EXPLAINS.get(self.target_id, {}).get(workload_id)
        if approved is None:
            raise ValueError("workload is not approved for EXPLAIN")
        sql, params = approved
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(f"EXPLAIN (FORMAT JSON, COSTS TRUE) {sql}", params)
            return cursor.fetchone()["QUERY PLAN"][0]


APPROVED_EXPLAINS: dict[str, dict[str, tuple[str, tuple[Any, ...]]]] = {
    "airlines": {
        "passenger_lookup": (
            """SELECT t.passenger_name, count(*) AS segment_count,
                       max(f.scheduled_departure) AS latest_departure,
                       count(bp.boarding_no) AS boarded
                  FROM bookings.tickets t
                  JOIN bookings.segments s ON s.ticket_no = t.ticket_no
                  JOIN bookings.flights f ON f.flight_id = s.flight_id
                  LEFT JOIN bookings.boarding_passes bp
                    ON bp.ticket_no = s.ticket_no AND bp.flight_id = s.flight_id
                 WHERE lower(t.passenger_name) = (
                       SELECT lower(passenger_name) FROM bookings.tickets
                       ORDER BY ticket_no LIMIT 1)
                 GROUP BY t.passenger_name ORDER BY segment_count DESC""",
            (),
        )
    },
    "lego": {
        "parts_lookup": (
            """SELECT s.name, sum(ip.quantity) AS pieces
                 FROM lego_sets s
                 JOIN lego_inventories i ON i.set_num = s.set_num
                 JOIN lego_inventory_parts ip ON ip.inventory_id = i.id
                WHERE s.year >= %s GROUP BY s.name ORDER BY pieces DESC LIMIT 50""",
            (2015,),
        )
    },
}
