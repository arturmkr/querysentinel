DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'demo_workload') THEN
    CREATE ROLE demo_workload LOGIN;
  END IF;
END
$$;
ALTER ROLE demo_workload PASSWORD :'workload_password';
ALTER ROLE demo_workload SET default_transaction_read_only = on;
ALTER ROLE demo_workload SET statement_timeout = '30s';
GRANT CONNECT ON DATABASE airlines, lego TO demo_workload;
