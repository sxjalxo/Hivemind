"""sensor changes: non-persona configuration changes of a sensor, from when

Revision ID: e4b7c1d9a2f5
Revises: d9a4f2c8e1b6

A new table only; nothing existing is altered.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e4b7c1d9a2f5"
down_revision: Union[str, Sequence[str], None] = "d9a4f2c8e1b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sensor_changes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("honeypot_id", sa.String(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("detail", sa.String(), nullable=False),
        sa.Column("recorded_by", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sensor_changes_honeypot_id", "sensor_changes", ["honeypot_id"])


def downgrade() -> None:
    op.drop_index("ix_sensor_changes_honeypot_id", table_name="sensor_changes")
    op.drop_table("sensor_changes")
