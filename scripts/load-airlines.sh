#!/bin/bash
set -euo pipefail

dump=${1:-demo-20250901-3m.sql}
test -f "$dump" || { echo "Missing $dump" >&2; exit 1; }
docker compose exec -T target-postgres sh -c 'test "$QS_DISPOSABLE_TARGET" = true'
docker compose exec -T target-postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS demo WITH (FORCE)" \
  -c "CREATE DATABASE demo"
docker compose exec -T target-postgres psql -U postgres -d postgres < "$dump"
docker compose exec -T target-postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "DROP DATABASE IF EXISTS airlines WITH (FORCE)" \
  -c "ALTER DATABASE demo RENAME TO airlines"
docker compose exec -T target-postgres psql -U postgres -d airlines -v ON_ERROR_STOP=1 \
  -f /workspace/scripts/sql/airlines-setup.sql
echo "Airlines loaded into disposable target-postgres only."
