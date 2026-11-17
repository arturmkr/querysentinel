"""Preserve the source username on performance samples."""

from alembic import op

revision = "0007_query_attribution"
down_revision = "0006_finding_max_age_error_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE query_interval_metrics ADD COLUMN IF NOT EXISTS username TEXT")


def downgrade() -> None:
    op.drop_column("query_interval_metrics", "username")
