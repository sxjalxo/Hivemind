"""persona deployments: which persona each sensor ran, from when

Revision ID: d9a4f2c8e1b6
Revises: c4e1a7d9f203

A new table only; nothing existing is altered.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d9a4f2c8e1b6"
down_revision: Union[str, Sequence[str], None] = "c4e1a7d9f203"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "persona_deployments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.String(), nullable=False),
        sa.Column("persona", sa.String(), nullable=False),
        sa.Column("digest", sa.String(), nullable=False),
        sa.Column("deployed_by", sa.String(), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_persona_deployments_honeypot_id", "persona_deployments", ["honeypot_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_persona_deployments_honeypot_id", table_name="persona_deployments")
    op.drop_table("persona_deployments")
