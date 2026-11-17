FROM ghcr.io/astral-sh/uv:0.11.21 AS uv
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

COPY --from=uv /uv /uvx /bin/
WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
COPY alembic ./alembic
COPY alembic.ini config.yaml ./
COPY scripts ./scripts
COPY docs/assets/querysentinel-logo.png ./docs/assets/querysentinel-logo.png
RUN uv sync --locked --no-dev

ENV PATH="/app/.venv/bin:$PATH"
CMD ["python", "-m", "querysentinel.worker"]
