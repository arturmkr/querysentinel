"""Add persisted synthetic workload jobs."""

from alembic import op
from querysentinel.models import SyntheticWorkloadJob

revision = "0004_synthetic_workload_jobs"
down_revision = "0003_finding_query_text"
branch_labels = None
depends_on = None


def upgrade() -> None:
    SyntheticWorkloadJob.__table__.create(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    SyntheticWorkloadJob.__table__.drop(bind=op.get_bind(), checkfirst=True)
