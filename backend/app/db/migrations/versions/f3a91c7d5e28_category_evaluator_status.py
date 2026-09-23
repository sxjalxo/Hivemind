"""per-characteristic evaluator status and detail

Revision ID: f3a91c7d5e28
Revises: d2f8b4c61e07

Why the backfill is a constant and not the run's own `evaluator_status`:
that column is an aggregate across all six characteristics, and it is lossy
in the dangerous direction. `any FAILED -> FAILED; else any COMPLETED ->
COMPLETED` means a run marked COMPLETED may contain a characteristic the
evaluator never assessed. Copying `completed` down onto that row would
manufacture the exact false `fixed` this column exists to prevent, and freeze
it into the data as though it had been measured.

Historic rows therefore say `unrecorded` -- we do not know -- and lifecycle
resolution falls back to the old run-level rule for them.

Nullable -> backfill -> NOT NULL, with NO server_default, matching
`c7d3e1a95b42` and `d2f8b4c61e07`.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f3a91c7d5e28"
down_revision: Union[str, Sequence[str], None] = "d2f8b4c61e07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "evaluation_category_scores",
        sa.Column("evaluator_status", sa.String(), nullable=True),
    )
    op.add_column(
        "evaluation_category_scores",
        sa.Column("evaluator_detail", sa.String(), nullable=True),
    )
    op.execute(
        "UPDATE evaluation_category_scores "
        "SET evaluator_status = 'unrecorded' "
        "WHERE evaluator_status IS NULL"
    )
    op.alter_column(
        "evaluation_category_scores",
        "evaluator_status",
        existing_type=sa.String(),
        nullable=False,
    )
    op.create_index(
        "ix_evaluation_category_scores_evaluator_status",
        "evaluation_category_scores",
        ["evaluator_status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_evaluation_category_scores_evaluator_status",
        table_name="evaluation_category_scores",
    )
    op.drop_column("evaluation_category_scores", "evaluator_detail")
    op.drop_column("evaluation_category_scores", "evaluator_status")
