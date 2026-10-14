"""claim rejections: why a claim was refused

Revision ID: b8e2d4f61a09
Revises: a4c9e2f7b1d3

A new table only. Analyses written before it have a `rejected_claims` count
and no rows to explain it; nothing can be backfilled, because the refused
claims were never stored.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b8e2d4f61a09"
down_revision: Union[str, Sequence[str], None] = "a4c9e2f7b1d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "claim_rejections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("technique_id", sa.String(), nullable=True),
        sa.Column("text", sa.String(), nullable=True),
        sa.Column("cited_event_ids", postgresql.ARRAY(sa.String()), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_claim_rejections_analysis_id", "claim_rejections", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_claim_rejections_analysis_id", table_name="claim_rejections")
    op.drop_table("claim_rejections")
