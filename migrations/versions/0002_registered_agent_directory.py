"""0002: registered_agents directory columns + atomic handle uniqueness

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-20 00:00:00.000000

The agent directory (handle, agent_card) was added to the ORM model in a
later commit than 0001 and was only ever created by ``Base.metadata
.create_all()`` at startup, so migrations alone produced an incomplete
schema. This revision is idempotent: it adds whatever is missing, so it is
safe both for databases created by create_all() and for databases that only
ever ran 0001.

It also replaces the full unique constraint on ``handle`` with a PARTIAL
unique index (WHERE handle IS NOT NULL). A partial index is required so that
``INSERT ... ON CONFLICT (handle)`` can arbitrate handle claims atomically
while still allowing many agents to have no handle. A full unique index
treats NULLs as distinct already, but it cannot serve as a conflict target
for an insert that also collides on the agent_id primary key.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

HANDLE_UNIQUE_INDEX = "uq_registered_agents_handle"
HANDLE_PLAIN_INDEX = "ix_registered_agents_handle"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    columns = {c["name"] for c in inspector.get_columns("registered_agents")}
    if "handle" not in columns:
        op.add_column(
            "registered_agents",
            sa.Column("handle", sa.String(64), nullable=True),
        )
    if "agent_card" not in columns:
        op.add_column(
            "registered_agents",
            sa.Column(
                "agent_card",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=True,
            ),
        )

    # Drop any pre-existing UNIQUE constraint on handle so the partial index
    # can act as the single arbiter for handle claims.
    for constraint in inspector.get_unique_constraints("registered_agents"):
        if constraint.get("column_names") == ["handle"]:
            op.drop_constraint(
                constraint["name"], "registered_agents", type_="unique"
            )

    # Unique indexes created by create_all() carry the model's index name.
    # (The plain ix_registered_agents_handle index is intentionally NOT
    # recreated: the partial unique index below also serves lookups by handle
    # for the non-NULL values a handle lookup can ever match.)
    index_names = {i["name"] for i in inspector.get_indexes("registered_agents")}
    for name in (HANDLE_UNIQUE_INDEX, HANDLE_PLAIN_INDEX):
        if name in index_names:
            op.drop_index(name, table_name="registered_agents")

    op.create_index(
        HANDLE_UNIQUE_INDEX,
        "registered_agents",
        ["handle"],
        unique=True,
        postgresql_where=sa.text("handle IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(HANDLE_UNIQUE_INDEX, table_name="registered_agents")
    op.create_index(
        HANDLE_PLAIN_INDEX,
        "registered_agents",
        ["handle"],
        unique=False,
    )
