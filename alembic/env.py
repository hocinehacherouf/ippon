"""Alembic environment.

The database URL is read from ``ippon.config.Settings.database_url`` (which
itself reads ``DATABASE_URL`` from the environment / ``.env``). ``alembic.ini``
intentionally has no URL — there's a single source of truth.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from ippon.config import get_settings

# Importing the models package eagerly registers all model classes onto
# ``Base.metadata`` so that ``autogenerate`` can see them.
from ippon.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Pull the live DB URL from settings; override the empty value in alembic.ini.
config.set_main_option("sqlalchemy.url", get_settings().database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without a DBAPI connection (emits SQL to stdout)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
