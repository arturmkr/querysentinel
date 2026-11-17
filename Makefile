.PHONY: up down demo demo-load-airlines demo-load-lego demo-verify demo-baseline demo-regression demo-recovery demo-lego test test-integration test-live test-all-free lint format

up:
	docker compose up -d --build

down:
	docker compose down

demo:
	docker compose up -d --build --wait
	$(MAKE) demo-load-lego
	$(MAKE) demo-lego

demo-load-airlines:
	bash scripts/load-airlines.sh

demo-load-lego:
	dump=$$(uv run python scripts/demo_dataset.py) && bash scripts/load-lego.sh "$$dump"

demo-verify:
	bash scripts/verify-demo.sh

demo-baseline:
	uv run --env-file .env python scripts/demo_scenario.py baseline

demo-regression:
	uv run --env-file .env python scripts/demo_scenario.py regression

demo-recovery:
	uv run --env-file .env python scripts/demo_scenario.py recovery

demo-lego:
	uv run --env-file .env python scripts/demo_scenario.py lego

test:
	uv run pytest tests/unit tests/api

test-integration:
	uv run pytest tests/integration

test-live:
	uv run $(if $(wildcard .env),--env-file .env) pytest tests/e2e -m live_ai -v -s

test-all-free:
	uv run pytest -m "not live_ai"

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
