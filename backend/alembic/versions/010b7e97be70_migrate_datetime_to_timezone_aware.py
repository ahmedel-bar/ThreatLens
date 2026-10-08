"""migrate_datetime_to_timezone_aware

Revision ID: 010b7e97be70
Revises: 64c7a8b65f57
Create Date: 2026-09-04 22:00:19.596897

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '010b7e97be70'
down_revision: Union[str, Sequence[str], None] = '64c7a8b65f57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: ensure all datetime columns are TIMESTAMP WITH TIME ZONE."""
    with op.batch_alter_table('investigations') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)
        batch_op.alter_column('updated_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)

    with op.batch_alter_table('investigation_events') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)

    with op.batch_alter_table('iocs') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)

    with op.batch_alter_table('pivot_runs') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)

    with op.batch_alter_table('provider_results') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)

    with op.batch_alter_table('relationships') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(timezone=True),
                              existing_type=sa.DateTime(),
                              nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('relationships') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)

    with op.batch_alter_table('provider_results') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)

    with op.batch_alter_table('pivot_runs') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)

    with op.batch_alter_table('iocs') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)

    with op.batch_alter_table('investigation_events') as batch_op:
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)

    with op.batch_alter_table('investigations') as batch_op:
        batch_op.alter_column('updated_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)
        batch_op.alter_column('created_at',
                              type_=sa.DateTime(),
                              existing_type=sa.DateTime(timezone=True),
                              nullable=True)
