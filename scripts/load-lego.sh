#!/bin/bash
set -euo pipefail

dump=${1:?Usage: load-lego.sh path/to/lego.sql}
docker compose exec -T target-postgres sh -c 'test "$QS_DISPOSABLE_TARGET" = true'
psql=(docker compose exec -T target-postgres psql -X -U postgres -d lego -v ON_ERROR_STOP=1)
existing=$("${psql[@]}" -Atc "SELECT to_regclass('public.lego_inventory_parts') IS NOT NULL")
if [[ $existing == t ]]; then
  echo "LEGO is already loaded."
  exit 0
fi
if [[ $("${psql[@]}" -Atc "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'") != 0 ]]; then
  echo "The LEGO database already contains tables. Use a fresh demo project." >&2
  exit 1
fi
"${psql[@]}" --single-transaction -f - < "$dump"
"${psql[@]}" -c "ANALYZE"
echo "LEGO loaded."
