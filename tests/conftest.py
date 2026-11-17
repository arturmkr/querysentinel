from __future__ import annotations

import pydantic_ai.models
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from querysentinel.models import Base

pydantic_ai.models.ALLOW_MODEL_REQUESTS = False


@pytest.fixture
def session():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db_session:
        yield db_session
    Base.metadata.drop_all(engine)
