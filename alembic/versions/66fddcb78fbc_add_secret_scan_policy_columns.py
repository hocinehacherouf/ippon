"""add secret scan policy columns

Revision ID: 66fddcb78fbc
Revises: 9539a84c02e4
Create Date: 2026-06-28 14:26:40.995846

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '66fddcb78fbc'
down_revision: Union[str, Sequence[str], None] = '9539a84c02e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_policies",
        sa.Column("secret_scan_enabled", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.add_column(
        "scan_policies",
        sa.Column("verify_secrets", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "scan_policies",
        sa.Column("secret_history_depth", sa.Integer(), nullable=False, server_default="256"),
    )


def downgrade() -> None:
    op.drop_column("scan_policies", "secret_history_depth")
    op.drop_column("scan_policies", "verify_secrets")
    op.drop_column("scan_policies", "secret_scan_enabled")
