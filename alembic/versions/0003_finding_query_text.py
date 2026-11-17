"""Persist the normalized SQL statement on every finding."""

from alembic import op

revision = "0003_finding_query_text"
down_revision = "0002_job_backoff"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS query_text TEXT")
    op.execute(
        """
        UPDATE findings AS f
           SET query_text = (
              SELECT m.query_text
                FROM query_interval_metrics AS m
               WHERE m.target_id = f.target_id
                 AND m.fingerprint = f.query_fingerprint
               ORDER BY m.interval_end DESC
               LIMIT 1
          )
         WHERE f.query_text IS NULL
        """
    )
    op.execute(
        "UPDATE findings SET query_text = '<statement unavailable>' WHERE query_text IS NULL"
    )
    op.execute("ALTER TABLE findings ALTER COLUMN query_text SET NOT NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS query_text")
