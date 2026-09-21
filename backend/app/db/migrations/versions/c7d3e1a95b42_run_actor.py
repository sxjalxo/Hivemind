"""who started an evaluation run

Adds `evaluation_runs.started_by` and `started_by_label`.

An evaluation resets a honeypot's container and executes attack chains against
it. "Who did this" is therefore a question the record should be able to
answer, and until now it could not.

`started_by` is NOT NULL and prefixed rather than a bare user id, because
three different situations would otherwise all be a null:

  user:<clerk_id>   an authenticated caller
  unauthenticated   CLERK_ISSUER was unset, so no identity existed to record
  unrecorded        the run predates this column

Existing rows are backfilled with `unrecorded`, and the distinction matters:
a run from before the audit trail existed is not an anonymous run. Reading it
as one would put a gap in the history and an action with no actor on exactly
equal footing, which is the same collapse `undetermined` exists to prevent for
findings. This mirrors the `legacy:` prefix `finding_key` uses for rows
written before their question was asked.

`started_by_label` stays nullable: it is the actor's email as the token
asserted it at the time, a convenience for a human reading the history and
never the identity. An email can be changed or reassigned; a Clerk user id
cannot.

Revision ID: c7d3e1a95b42
Revises: b1f4c2a37e90
Create Date: 2026-09-21

"""
from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c7d3e1a95b42"
down_revision: Union[str, Sequence[str], None] = "b1f4c2a37e90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add nullable, backfill, then tighten to NOT NULL.

    Three steps rather than one `server_default`: a default would silently
    apply to future inserts too, so an application path that forgot to supply
    an actor would land rows marked `unrecorded` -- which is supposed to mean
    "written before this column existed" and nothing else. The default is
    dropped at the end so that meaning stays true.
    """
    op.add_column(
        "evaluation_runs",
        sa.Column("started_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.add_column(
        "evaluation_runs",
        sa.Column("started_by_label", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.execute("UPDATE evaluation_runs SET started_by = 'unrecorded' WHERE started_by IS NULL")
    op.alter_column("evaluation_runs", "started_by", nullable=False)
    op.create_index(
        "ix_evaluation_runs_started_by", "evaluation_runs", ["started_by"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_evaluation_runs_started_by", table_name="evaluation_runs")
    op.drop_column("evaluation_runs", "started_by_label")
    op.drop_column("evaluation_runs", "started_by")
