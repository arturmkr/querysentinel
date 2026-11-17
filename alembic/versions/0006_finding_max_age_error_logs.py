"""Expire findings by age and persist PostgreSQL log positions."""

from alembic import op

revision = "0006_finding_max_age_error_logs"
down_revision = "0005_accumulated_samples"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolution_reason VARCHAR(32)")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS healthy_observations")
    op.execute(
        "CREATE TABLE IF NOT EXISTS error_log_checkpoints "
        "(target_id VARCHAR(63) PRIMARY KEY, source TEXT NOT NULL, positions JSON NOT NULL)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS error_log_checkpoints")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS resolution_reason")
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS healthy_observations INTEGER NOT NULL DEFAULT 0"
    )
