"""session annotations: analyst tags and notes

Revision ID: a4c9e2f7b1d3
Revises: f3a91c7d5e28

A new table only; nothing existing is altered, so there is nothing to backfill.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a4c9e2f7b1d3"
down_revision: Union[str, Sequence[str], None] = "f3a91c7d5e28"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "session_annotations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("body", sa.String(), nullable=False),
        sa.Column("author", sa.String(), nullable=False),
        sa.Column("author_label", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_session_annotations_session_id", "session_annotations", ["session_id"])
    op.create_index(
        "uq_session_annotations_tag",
        "session_annotations",
        ["session_id", "body"],
        unique=True,
        postgresql_where=sa.text("kind = 'tag'"),
    )


def downgrade() -> None:
    op.drop_index("uq_session_annotations_tag", table_name="session_annotations")
    op.drop_index("ix_session_annotations_session_id", table_name="session_annotations")
    op.drop_table("session_annotations")
