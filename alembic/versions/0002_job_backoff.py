"""Add retry scheduling for bounded job backoff."""

from alembic import op

revision = "0002_job_backoff"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS next_attempt_at "
        "TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_scan_jobs_next_attempt_at ON scan_jobs (next_attempt_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_jobs_next_attempt_at")
    op.execute("ALTER TABLE scan_jobs DROP COLUMN IF EXISTS next_attempt_at")
