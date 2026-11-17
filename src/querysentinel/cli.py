from __future__ import annotations

import argparse

from querysentinel.config import load_project_config
from querysentinel.db import get_session_factory
from querysentinel.jobs import ActiveScanError, enqueue_job
from querysentinel.schemas import JobSource


def main() -> None:
    parser = argparse.ArgumentParser(prog="querysentinel")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="enqueue a target scan")
    scan_parser.add_argument("target_id")
    args = parser.parse_args()
    if args.command == "scan":
        target = load_project_config().target(args.target_id)
        if target is None:
            parser.error(f"unknown target: {args.target_id}")
        with get_session_factory()() as session:
            try:
                job = enqueue_job(session, target.id, JobSource.MANUAL)
            except ActiveScanError as exc:
                print(f"active scan: {exc.job.id}")
            else:
                print(job.id)


if __name__ == "__main__":
    main()
