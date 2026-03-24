"""create parse_websearch function

Revision ID: 771feda96f1c
Revises: 9e8c841d1a30
Create Date: 2026-03-24 00:00:00.000000

Not a duplicate of 7ce5925f832b. That migration created the old
tsq_search function. The sqlalchemy-searchable version bump (Werkzeug
3.x upgrade, #88) switched from tsq_search to parse_websearch, so this
migration creates the new function the library now expects.

7ce5925f832b has ``downgrade(): pass`` — we leave that untouched.
If this migration is downgraded the function is dropped; 7ce5925f832b's
no-op downgrade won't re-drop it, which is harmless.
"""
from alembic import op
from sqlalchemy_searchable import sql_expressions


# revision identifiers, used by Alembic.
revision = '771feda96f1c'
down_revision = '9e8c841d1a30'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(sql_expressions)


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS parse_websearch(regconfig, text)")
    op.execute("DROP FUNCTION IF EXISTS parse_websearch(text)")
