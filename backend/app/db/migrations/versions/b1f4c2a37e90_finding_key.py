"""finding identity across runs

Adds `evaluation_findings.finding_key`: the stable identity that lets two runs
be asked whether they are reporting the same defect.

NOT NULL rather than nullable-with-application-discipline, for the same reason
the evidence trigger is a trigger: a finding with no identity should be
unrepresentable, not merely discouraged. Every row written from here on can be
followed across runs.

Existing rows are backfilled with `legacy:<row id>`. Deliberately the row id
and not a hash of the content: the key has to be unique within a run, and two
identical findings in one pre-existing run would collide under a content hash
and fail the unique index halfway through a migration. A content hash would
also imply these legacy keys can be matched across runs, and they cannot --
they were written before any notion of identity existed, so the `legacy:`
prefix keeps them out of every lifecycle. Not knowing is the honest answer for
rows produced before the question was asked.

Revision ID: b1f4c2a37e90
Revises: ad6b0d86d035
Create Date: 2026-09-17

"""
from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b1f4c2a37e90"
down_revision: Union[str, Sequence[str], None] = "ad6b0d86d035"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the column nullable, backfill, then tighten to NOT NULL.

    Three steps rather than one: adding a NOT NULL column with no default to a
    table that already has rows fails outright, and a server_default would
    leave every legacy row sharing one key -- which the unique index below
    would then reject, after the column had already been added.
    """
    op.add_column(
        "evaluation_findings",
        sa.Column("finding_key", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.execute(
        "UPDATE evaluation_findings "
        "SET finding_key = 'legacy:' || id::text "
        "WHERE finding_key IS NULL"
    )
    op.alter_column("evaluation_findings", "finding_key", nullable=False)

    # The real guard. Two findings sharing a key within one run would make
    # "is it fixed?" ambiguous, and the answer would depend silently on row
    # order.
    op.create_index(
        "ix_findings_run_key",
        "evaluation_findings",
        ["run_id", "finding_key"],
        unique=True,
    )
    # Lifecycle looks a key up across a honeypot's history, so the key needs
    # its own index; the composite above cannot serve a query that does not
    # constrain run_id.
    op.create_index("ix_findings_key", "evaluation_findings", ["finding_key"])


def downgrade() -> None:
    op.drop_index("ix_findings_key", table_name="evaluation_findings")
    op.drop_index("ix_findings_run_key", table_name="evaluation_findings")
    op.drop_column("evaluation_findings", "finding_key")
