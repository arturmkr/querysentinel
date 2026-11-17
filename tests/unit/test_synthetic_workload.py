from __future__ import annotations

import pytest

from querysentinel.synthetic_workload import (
    QueryBatch,
    _read_only_queries,
    load_or_generate_queries,
)


def test_only_select_and_with_statements_are_accepted() -> None:
    assert _read_only_queries([" SELECT 1; ", "WITH x AS (SELECT 1) SELECT * FROM x"])[0] == (
        "SELECT 1"
    )
    with pytest.raises(ValueError, match="read-only"):
        _read_only_queries(["DELETE FROM lego_sets", "DROP TABLE lego_parts"])


def test_cached_workload_never_calls_model(monkeypatch, tmp_path) -> None:
    cache = tmp_path / "synthetic_workload_lego.json"
    cache.write_text(QueryBatch(queries=["SELECT 1", "SELECT 2"]).model_dump_json())
    monkeypatch.setattr(
        "querysentinel.synthetic_workload.generate_queries",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("model called")),
    )

    queries, generated = load_or_generate_queries(
        dsn="postgresql://unused",
        model="test",
        target_id="lego",
        count=2,
        fresh=False,
        cache_dir=tmp_path,
    )

    assert queries == ["SELECT 1", "SELECT 2"]
    assert generated is False
