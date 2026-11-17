<img align="right" src="docs/assets/querysentinel-logo.png" alt="QuerySentinel logo" width="96">

# QuerySentinel

PostgreSQL query monitoring and AI-assisted triage. QuerySentinel detects slowdowns and execution errors, tracks recurring findings, and gives operators a dashboard and an MCP endpoint to investigate them.

[![Tests](https://github.com/arturmkr/querysentinel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/arturmkr/querysentinel/actions/workflows/ci.yml)

The agent uses read-only database tools and suggests checks you can run to verify its findings. Detection works without a model API key.

### Try it on LEGO

Requires Docker Compose, Make, and [uv](https://docs.astral.sh/uv/). From the repository root:

```bash
cp .env.example .env
# Set the local passwords, UI_ADMIN_PASSWORD, and API_TOKEN in .env.
make demo
```

Open [the dashboard](http://127.0.0.1:8000/ui/), enter your `UI_ADMIN_PASSWORD`, and select **LEGO → Findings**. The demo downloads a pinned [LEGO snapshot](https://github.com/neondatabase/postgres-sample-dbs/tree/b54cb67534bf20775803b181b7a1c6f573422161), checks its SHA-256, and imports it into the local PostgreSQL container. It reuses an existing LEGO database and leaves the demo running. End it with `make down`.

The demo runs a query that sorts LEGO inventory parts by a computed value. Open its finding to see the normalized SQL, the `demo_workload` role, and the measured execution time and temporary I/O. The numbers come from your PostgreSQL run. To see the agent's investigation in the same card, set `OPENAI_API_KEY` in `.env` before starting the demo.

### How it works

- **Detect.** Scheduled or manual scans compare query statistics from `pg_stat_statements`. A separate reader turns failures from PostgreSQL JSON logs into findings with an error code and the observed user or client, when available.
- **Investigate.** Pydantic AI gives the agent read-only tools to inspect the measurements, table metadata, and indexes. The agent returns suspected causes, recommendations, and steps to verify them. Monitoring continues when the model is unavailable.
- **Track.** Findings record when a problem was last observed. The first successful scan after the configured quiet period closes the finding. If the problem comes back, the same finding reopens.

The local PostgreSQL logs queries that take at least one second. Set `POSTGRES_LOG_MIN_DURATION_STATEMENT` in `.env` to change that threshold. For an external PostgreSQL, enable JSON logs with query IDs and `log_min_duration_statement`, keep English log messages (`lc_messages = 'C'`), and configure the target's `error_log_dir` and `error_log_database`. Applications supply `application_name` when connecting. QuerySentinel matches logged executions by target, query ID, database user and sample time. Counts by client cover executions present in the logs. PostgreSQL's raw duration logs can include SQL literals. QuerySentinel stores attribution metadata from those records.

The project uses Python, FastAPI, a background worker, PostgreSQL for its own state, and a NiceGUI dashboard that calls the REST API. The default Compose setup is for local development. The API is documented at [/docs](http://127.0.0.1:8000/docs).

### Connect an MCP client

QuerySentinel exposes a Streamable HTTP MCP endpoint at
[`http://127.0.0.1:8000/mcp/`](http://127.0.0.1:8000/mcp/). It uses the same static
bearer token as the REST API; configure the client to send:

```text
Authorization: Bearer <API_TOKEN>
```

The MCP server provides six structured tools: `list_targets`, `list_scans`, `get_scan`,
`list_findings`, `get_finding`, and `start_scan`. Starting a scan is asynchronous; poll it with
`get_scan`. If a target already has an active scan, `start_scan` returns that scan with
`created=false` instead of queuing a duplicate. SQL text and database evidence returned by the
tools are untrusted data and must not be treated as instructions.

Localhost is allowed by default. For a remote deployment, set `MCP_ALLOWED_HOSTS` and, for browser
clients that send an `Origin` header, `MCP_ALLOWED_ORIGINS` as JSON arrays. Keep the endpoint behind
HTTPS and do not expose it without `API_TOKEN`.

### Run the tests

```bash
make test              # unit and API tests
make test-integration  # requires Docker
make lint
```

The standard tests use their own fixtures and disposable Testcontainers databases. They need neither the demo dumps nor an API key. The optional live AI test uses the same verified LEGO snapshot. To enable it, set `LIVE_AI_TESTS=true`, `OPENAI_API_KEY`, `AI_MODEL`, and the model's per-million-token prices in `LIVE_AI_INPUT_PRICE_PER_MILLION_USD` and `LIVE_AI_OUTPUT_PRICE_PER_MILLION_USD`, then run `make test-live`.

[MIT License](LICENSE).
