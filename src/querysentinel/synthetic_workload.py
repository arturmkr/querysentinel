"""Small, opt-in synthetic read-only workload for validating a demo installation."""

from __future__ import annotations

from pathlib import Path

import psycopg
from pydantic import BaseModel, Field
from pydantic_ai import Agent


class QueryBatch(BaseModel):
    queries: list[str] = Field(min_length=1, max_length=50)


class WorkloadResult(BaseModel):
    generated: bool
    succeeded: int
    failed: int


def cache_path(cache_dir: Path, target_id: str) -> Path:
    return cache_dir / f"synthetic_workload_{target_id}.json"


def read_schema(dsn: str) -> str:
    with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT table_schema, table_name, column_name, data_type
              FROM information_schema.columns
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
             ORDER BY table_schema, table_name, ordinal_position
            """
        )
        return "\n".join(".".join(row) for row in cursor.fetchall())


def generate_queries(model: str, target_id: str, schema: str, count: int) -> list[str]:
    agent = Agent(
        model,
        output_type=QueryBatch,
        instructions=(
            "Generate valid PostgreSQL read-only workload statements for a disposable demo "
            "database. Use only SELECT or WITH. Make statements structurally different. "
            "Intentionally include expensive real patterns such as joins, aggregations, sorting, "
            "ILIKE/text transformations, correlated subqueries, window functions and CTEs. "
            "Use only supplied schema objects; no placeholders and no pg_sleep."
        ),
    )
    result = agent.run_sync(
        f"Target: {target_id}\nGenerate exactly {count} queries.\n\nSchema:\n{schema}"
    )
    return _read_only_queries(result.output.queries)[:count]


def _read_only_queries(queries: list[str]) -> list[str]:
    accepted: list[str] = []
    for query in queries:
        normalized = query.strip().rstrip(";").strip()
        if normalized.lower().startswith(("select ", "with ")):
            accepted.append(normalized)
    if not accepted:
        raise ValueError("model did not return any read-only SELECT/WITH statements")
    return accepted


def load_or_generate_queries(
    *,
    dsn: str,
    model: str,
    target_id: str,
    count: int,
    fresh: bool,
    cache_dir: Path,
) -> tuple[list[str], bool]:
    path = cache_path(cache_dir, target_id)
    if path.exists() and not fresh:
        queries = _read_only_queries(QueryBatch.model_validate_json(path.read_text()).queries)
        return queries[:count], False
    queries = generate_queries(model, target_id, read_schema(dsn), count)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(QueryBatch(queries=queries).model_dump_json(indent=2))
    return queries, True


def execute_workload(dsn: str, queries: list[str], rounds: int) -> tuple[int, int]:
    succeeded = 0
    failed = 0
    with psycopg.connect(
        dsn,
        autocommit=True,
        options=(
            "-c default_transaction_read_only=on "
            "-c statement_timeout=30000 "
            "-c lock_timeout=2000 "
            "-c application_name=querysentinel_synthetic_workload"
        ),
    ) as connection:
        for _ in range(rounds):
            for query in queries:
                try:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        cursor.fetchone() if cursor.description else None
                except Exception:
                    failed += 1
                else:
                    succeeded += 1
    return succeeded, failed


def run_synthetic_workload(
    *,
    dsn: str,
    model: str,
    target_id: str,
    query_count: int,
    rounds: int,
    fresh: bool,
    cache_dir: Path,
) -> WorkloadResult:
    queries, generated = load_or_generate_queries(
        dsn=dsn,
        model=model,
        target_id=target_id,
        count=query_count,
        fresh=fresh,
        cache_dir=cache_dir,
    )
    succeeded, failed = execute_workload(dsn, queries, rounds)
    return WorkloadResult(generated=generated, succeeded=succeeded, failed=failed)
