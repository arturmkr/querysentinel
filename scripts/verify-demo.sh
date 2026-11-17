#!/bin/bash
set -euo pipefail

docker compose exec -T target-postgres psql -U postgres -d airlines -v ON_ERROR_STOP=1 \
  -c "SELECT current_database(), count(*) AS flights FROM bookings.flights" \
  -c "SELECT extname FROM pg_extension WHERE extname = 'pg_stat_statements'"
docker compose exec -T target-postgres psql -U postgres -d lego -v ON_ERROR_STOP=1 \
  -c "SELECT current_database(), (SELECT count(*) FROM lego_sets) AS sets, (SELECT count(*) FROM lego_inventory_parts) AS inventory_parts" \
  -c "SELECT extname FROM pg_extension WHERE extname = 'pg_stat_statements'"
docker compose exec -T sentinel-postgres psql -U sentinel -d sentinel -v ON_ERROR_STOP=1 \
  -c "SELECT current_database() AS isolated_state_database"
