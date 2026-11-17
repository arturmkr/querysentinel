CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE INDEX IF NOT EXISTS qs_tickets_lower_passenger_name_idx
    ON bookings.tickets (lower(passenger_name));
ANALYZE;
GRANT USAGE ON SCHEMA bookings, public TO sentinel_monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA bookings, public TO sentinel_monitor;
ALTER DEFAULT PRIVILEGES IN SCHEMA bookings GRANT SELECT ON TABLES TO sentinel_monitor;
GRANT USAGE ON SCHEMA bookings, public TO demo_workload;
GRANT SELECT ON ALL TABLES IN SCHEMA bookings, public TO demo_workload;
ALTER DEFAULT PRIVILEGES IN SCHEMA bookings GRANT SELECT ON TABLES TO demo_workload;
