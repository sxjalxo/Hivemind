"""drop attacker_profiles: a table nothing ever read or wrote

Revision ID: c4e1a7d9f203
Revises: b8e2d4f61a09

Created by the initial schema for cached attacker profiles, but profiles have
always been built on the fly from Elasticsearch (`app.services.profiles`), so
the table stayed empty. Dropped rather than kept as a second, silent source of
truth. The downgrade recreates it exactly as the initial migration did.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4e1a7d9f203"
down_revision: Union[str, Sequence[str], None] = "b8e2d4f61a09"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_table("attacker_profiles")


def downgrade() -> None:
    op.create_table(
        "attacker_profiles",
        sa.Column("ip", sa.String(), nullable=False),
        sa.Column("risk", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("behavior_label", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("geo", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("ip"),
    )
