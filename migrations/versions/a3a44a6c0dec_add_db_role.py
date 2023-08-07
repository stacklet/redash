"""Add db_role column to Users and QueryResults.

Revision ID: a3a44a6c0dec
Revises: 89bc7873a3e0
Create Date: 2023-08-04 17:47:29.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "a3a44a6c0dec"
down_revision = "89bc7873a3e0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column(
            "db_role",
            sa.String(128),
            nullable=True,
        ),
    )
    op.add_column(
        "query_results",
        sa.Column(
            "db_role",
            sa.String(128),
            nullable=True,
        ),
    )
    op.execute(
        """
        CREATE POLICY limited_query_results ON query_results
          AS RESTRICTIVE
          FOR SELECT
          TO limited_visibility
          WITH CHECK current_user = db_role;
        """
    )


def downgrade():
    op.drop_column("users", "db_role")
    op.drop_column("query_results", "db_role")
