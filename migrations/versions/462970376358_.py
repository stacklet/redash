"""
Merge heads... due to the enhancements we've made we have two
alembic heads, this should allow us to merge the changes together

Revision ID: 462970376358
Revises: 4afa4a1dd310, 7205816877ec
Create Date: 2024-02-29 18:57:43.748725

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '462970376358'
down_revision = ('4afa4a1dd310', '7205816877ec')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
