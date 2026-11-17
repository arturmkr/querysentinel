"""Preserve incomplete query samples and identify cumulative measurements."""

from alembic import op

revision = "0005_accumulated_samples"
down_revision = "0004_synthetic_workload_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE query_counter_snapshots ADD COLUMN IF NOT EXISTS pending_sample JSON")
    op.execute(
        "ALTER TABLE query_counter_snapshots ADD COLUMN IF NOT EXISTS counter_epoch_start TIMESTAMPTZ"
    )
    op.execute(
        "ALTER TABLE query_interval_metrics ADD COLUMN IF NOT EXISTS sample_scope VARCHAR(16) NOT NULL DEFAULT 'interval'"
    )
    op.execute(
        "ALTER TABLE query_interval_metrics ADD COLUMN IF NOT EXISTS counter_epoch_start TIMESTAMPTZ"
    )


def downgrade() -> None:
    op.drop_column("query_interval_metrics", "counter_epoch_start")
    op.drop_column("query_interval_metrics", "sample_scope")
    op.drop_column("query_counter_snapshots", "counter_epoch_start")
    op.drop_column("query_counter_snapshots", "pending_sample")
