from __future__ import annotations

from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from querysentinel.config import get_settings


@lru_cache
def get_engine() -> Engine:
    return create_engine(
        get_settings().sentinel_database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(get_engine(), expire_on_commit=False)


def session_dependency():
    with get_session_factory()() as session:
        yield session
