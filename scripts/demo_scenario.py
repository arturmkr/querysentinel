from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "http://127.0.0.1:8000"
TOKEN = os.environ["API_TOKEN"]


def api(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    request = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = json.load(exc)
        if exc.code == 409 and isinstance(detail["detail"], dict) and "scan_id" in detail["detail"]:
            return {"scan_id": detail["detail"]["scan_id"]}
        raise


def scan(target: str) -> dict:
    created = api("/api/v1/scans", "POST", {"target_id": target})
    scan_id = created["scan_id"]
    for _ in range(180):
        result = api(f"/api/v1/scans/{scan_id}")
        if result["status"] in {"COMPLETED", "FAILED"}:
            if result["status"] == "FAILED":
                raise RuntimeError(result.get("error") or "scan failed")
            return result
        time.sleep(1)
    raise TimeoutError(f"scan {scan_id} did not finish")


def psql(database: str, command: str) -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "target-postgres",
            "psql",
            "-U",
            "postgres",
            "-d",
            database,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            command,
        ],
        check=True,
    )


def workload(database: str, file_name: str, transactions: int = 10) -> None:
    # The public LEGO example runs with the same read-only account as synthetic workloads.
    connection = ["-U", "postgres"]
    command = ["pgbench"]
    if database == "lego":
        command = ["sh", "-c", 'PGPASSWORD="$DEMO_WORKLOAD_PASSWORD" exec "$@"', "--", "pgbench"]
        connection = ["-h", "127.0.0.1", "-U", "demo_workload"]
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "target-postgres",
            *command,
            *connection,
            "-d",
            database,
            "-n",
            "-c",
            "2",
            "-j",
            "2",
            "-t",
            str(transactions),
            "-f",
            f"/workspace/scripts/sql/{file_name}",
        ],
        check=True,
    )


def main() -> None:
    action = sys.argv[1]
    if action == "baseline":
        psql(
            "airlines",
            "CREATE INDEX IF NOT EXISTS qs_tickets_lower_passenger_name_idx "
            "ON bookings.tickets (lower(passenger_name)); "
            "ANALYZE bookings.tickets",
        )
        psql("airlines", "SELECT pg_stat_statements_reset()")
        workload("airlines", "airlines-workload.sql", transactions=1)
        scan("airlines")
        workload("airlines", "airlines-workload.sql")
        print(json.dumps(scan("airlines"), indent=2))
    elif action == "regression":
        psql(
            "airlines",
            "DROP INDEX IF EXISTS bookings.qs_tickets_lower_passenger_name_idx; "
            "ANALYZE bookings.tickets",
        )
        workload("airlines", "airlines-workload.sql")
        print(json.dumps(scan("airlines"), indent=2))
    elif action == "recovery":
        psql(
            "airlines",
            "CREATE INDEX IF NOT EXISTS qs_tickets_lower_passenger_name_idx "
            "ON bookings.tickets (lower(passenger_name)); "
            "ANALYZE bookings.tickets",
        )
        workload("airlines", "airlines-workload.sql")
        print(json.dumps(scan("airlines"), indent=2))
    elif action == "lego":
        for _ in range(2):
            workload("lego", "lego-workload.sql", transactions=5)
            result = scan("lego")
        findings = api(f"/api/v1/findings?scan_id={result['scan_id']}")
        sort_findings = [
            item for item in findings["items"] if "AS sorted_parts" in item["query_text"]
        ]
        if not sort_findings:
            raise RuntimeError("The LEGO sort did not cross a detection threshold")
        for finding in sort_findings:
            print(f"{finding['summary']} (finding {finding['id']})")
        print("Open http://127.0.0.1:8000/ui/ and select LEGO → Findings.")
    else:
        raise SystemExit(f"unknown scenario: {action}")


if __name__ == "__main__":
    main()
