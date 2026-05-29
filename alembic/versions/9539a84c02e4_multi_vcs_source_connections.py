"""multi-vcs source connections

Revision ID: 9539a84c02e4
Revises: 8c8832ce9746
Create Date: 2026-05-29 23:11:00.117451

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9539a84c02e4'
down_revision: Union[str, Sequence[str], None] = '8c8832ce9746'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add the 'none' credential type for anonymous / public-repo connections.
    # Autogenerate doesn't diff enum values, so this is hand-added. PG16 allows
    # ADD VALUE inside a transaction as long as the value isn't used in the
    # same transaction (it isn't here).
    op.execute("ALTER TYPE source_credential_type ADD VALUE IF NOT EXISTS 'none'")

    op.add_column(
        'source_connections',
        sa.Column('webhook_secret_blob', sa.LargeBinary(), nullable=True),
    )
    op.alter_column(
        'source_connections', 'credential_blob',
        existing_type=postgresql.BYTEA(), nullable=True,
    )
    op.alter_column(
        'source_connections', 'credential_kid',
        existing_type=sa.VARCHAR(length=64), nullable=True,
    )
    op.create_unique_constraint(
        op.f('uq_source_connections_org_id_name'),
        'source_connections', ['org_id', 'name'],
    )


def downgrade() -> None:
    """Downgrade schema.

    Note: PostgreSQL cannot drop an enum value, so 'none' is left on
    ``source_credential_type``. Re-tightening the NOT NULL constraints will
    fail if any anonymous connections (NULL credential_blob) were created
    after the upgrade — clean those rows first if you must downgrade.
    """
    op.drop_constraint(
        op.f('uq_source_connections_org_id_name'),
        'source_connections', type_='unique',
    )
    op.alter_column(
        'source_connections', 'credential_kid',
        existing_type=sa.VARCHAR(length=64), nullable=False,
    )
    op.alter_column(
        'source_connections', 'credential_blob',
        existing_type=postgresql.BYTEA(), nullable=False,
    )
    op.drop_column('source_connections', 'webhook_secret_blob')
