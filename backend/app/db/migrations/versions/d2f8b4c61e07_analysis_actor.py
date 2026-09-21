"""who ran an analysis

Adds `analyses.started_by` and `started_by_label`, mirroring the columns
migration c7d3e1a95b42 added to `evaluation_runs`.

An analysis costs a full LLM pipeline on the one GPU and writes claims the
interface presents as findings, so it is worth being able to say who asked for
it. The evaluation run was audited first because it also resets a container;
auditing one and not the other left a record that could answer the question
for half the actions that take one.

Same three-valued scheme, for the same reason:

  user:<clerk_id>   an authenticated caller
  unauthenticated   CLERK_ISSUER was unset, so no identity existed to record
  unrecorded        the analysis predates this column

Existing rows are backfilled `unrecorded`. A run from before the audit trail
is not an anonymous run, and an audit trail that says the same thing for both
lets a gap read as an anonymous action.

Revision ID: d2f8b4c61e07
Revises: c7d3e1a95b42
Create Date: 2026-09-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d2f8b4c61e07"
down_revision: Union[str, Sequence[str], None] = "c7d3e1a95b42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add nullable, backfill, then tighten to NOT NULL.

    No `server_default`: one would apply to future inserts too, so a code path
    that forgot to supply an actor would land rows marked `unrecorded` --
    which must keep meaning "written before this column existed" and nothing
    else.
    """
    op.add_column(
        "analyses",
        sa.Column("started_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.add_column(
        "analyses",
        sa.Column("started_by_label", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.execute("UPDATE analyses SET started_by = 'unrecorded' WHERE started_by IS NULL")
    op.alter_column("analyses", "started_by", nullable=False)
    op.create_index("ix_analyses_started_by", "analyses", ["started_by"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_analyses_started_by", table_name="analyses")
    op.drop_column("analyses", "started_by_label")
    op.drop_column("analyses", "started_by")
