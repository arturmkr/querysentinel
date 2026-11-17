#!/bin/bash
set -euo pipefail

psql --username postgres --dbname postgres -v ON_ERROR_STOP=1 \
  -v monitor_password="$TARGET_MONITOR_PASSWORD" <<'SQL'
CREATE DATABASE airlines;
CREATE DATABASE lego;
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_monitor') THEN
    CREATE ROLE sentinel_monitor LOGIN;
  END IF;
END
$$;
ALTER ROLE sentinel_monitor PASSWORD :'monitor_password';
ALTER ROLE sentinel_monitor SET default_transaction_read_only = on;
ALTER ROLE sentinel_monitor SET statement_timeout = '10s';
ALTER ROLE sentinel_monitor SET lock_timeout = '2s';
GRANT pg_read_all_stats TO sentinel_monitor;
GRANT CONNECT ON DATABASE airlines, lego TO sentinel_monitor;
SQL

psql --username postgres --dbname postgres -v ON_ERROR_STOP=1 \
  -v workload_password="$DEMO_WORKLOAD_PASSWORD" \
  -f /workspace/scripts/sql/configure-workload-role.sql

for database in airlines lego; do
  psql --username postgres --dbname "$database" -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
GRANT USAGE ON SCHEMA public TO sentinel_monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sentinel_monitor;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO sentinel_monitor;
GRANT USAGE ON SCHEMA public TO demo_workload;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO demo_workload;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO demo_workload;
SQL
done
