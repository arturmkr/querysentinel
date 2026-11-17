"""Keep PostgreSQL slow-query attribution across scans."""

from alembic import op
from querysentinel.models import SlowQueryObservation

revision = "0008_slow_query_sources"
down_revision = "0007_query_attribution"
branch_labels = None
depends_on = None


def upgrade() -> None:
    SlowQueryObservation.__table__.create(op.get_bind(), checkfirst=True)


def downgrade() -> None:
    SlowQueryObservation.__table__.drop(op.get_bind(), checkfirst=True)
