import time
import os
from urllib.parse import urlparse

from click import argument, option
from flask.cli import AppGroup
from flask_migrate import stamp
import sqlalchemy
from sqlalchemy.exc import DatabaseError
from sqlalchemy.sql import select
from sqlalchemy_utils.types.encrypted.encrypted_type import FernetEngine
import boto3

from redash import settings
from redash.models.base import Column, key_type
from redash.models.types import EncryptedConfiguration
from redash.utils.configuration import ConfigurationContainer

manager = AppGroup(help="Manage the database (create/drop tables. reencrypt data.).")

DBIAM_USER = os.environ["REDASH_DBIAM_USER"]
DBURI_TEMPLATE = os.environ["REDASH_DATABASE_URL"]


def get_db_auth_token(username, hostname, port):
    return boto3.client("rds").generate_db_auth_token(
        DBHostname=hostname, Port=port, DBUsername=username
    )


def get_iam_auth_dburi():
    global DBURI_TEMPLATE, DBIAM_USER
    db = urlparse(DBURI_TEMPLATE)
    db_cred = {
        "user": DBIAM_USER,
        "password": get_db_auth_token(DBIAM_USER, db.hostname, db.port),
    }
    return DBURI_TEMPLATE.format(**db_cred)


def redash_user_grant(engine, redash_engine):
    username = redash_engine.url.username
    password = redash_engine.url.password

    with engine.connect() as conn:
        conn.execute(f"CREATE USER IF NOT EXISTS {username} WITH PASSWORD '{password}'")
        conn.execute(
            f"GRANT USAGE ON SCHEMA {settings.SQLALCHEMY_DATABASE_SCHEMA} TO {username}"
        )
        conn.execute(
            f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA {settings.SQLALCHEMY_DATABASE_SCHEMA} TO {username}"
        )


def _wait_for_db_connection(db):
    retried = False
    while not retried:
        try:
            db.engine.execute("SELECT 1;")
            return
        except DatabaseError:
            time.sleep(30)

        retried = True


def is_db_empty():
    from redash.models import db

    extant_tables = set(sqlalchemy.inspect(db.get_engine()).get_table_names())
    redash_tables = set(db.metadata.tables)
    return len(redash_tables.intersection(extant_tables)) == 0


def load_extensions(db):
    with db.engine.connect() as connection:
        for extension in settings.dynamic_settings.database_extensions:
            connection.execute(f'CREATE EXTENSION IF NOT EXISTS "{extension}";')


@manager.command()
def create_tables():
    """Create the database tables."""
    from redash.models import db

    if is_db_empty():
        if settings.SQLALCHEMY_DATABASE_SCHEMA:
            from sqlalchemy import DDL
            from sqlalchemy import event

            event.listen(
                db.metadata,
                "before_create",
                DDL(
                    f"CREATE SCHEMA IF NOT EXISTS {settings.SQLALCHEMY_DATABASE_SCHEMA}"
                ),
            )

        iam_db_uri = get_iam_auth_dburi()
        grant_engine = sqlalchemy.engine.create_engine(iam_db_uri)
        redash_user_grant(grant_engine, db.engine)

        _wait_for_db_connection(db)

        # We need to make sure we run this only if the DB is empty, because otherwise calling
        # stamp() will stamp it with the latest migration value and migrations won't run.
        load_extensions(db)

        # To create triggers for searchable models, we need to call configure_mappers().
        sqlalchemy.orm.configure_mappers()
        db.create_all()

        # Need to mark current DB as up to date
        stamp()
    else:
        print("existing redash tables detected, exiting")


@manager.command()
def drop_tables():
    """Drop the database tables."""
    from redash.models import db

    _wait_for_db_connection(db)
    db.drop_all()


@manager.command()
@argument("old_secret")
@argument("new_secret")
@option("--show-sql/--no-show-sql", default=False, help="show sql for debug")
def reencrypt(old_secret, new_secret, show_sql):
    """Reencrypt data encrypted by OLD_SECRET with NEW_SECRET."""
    from redash.models import db

    _wait_for_db_connection(db)

    if show_sql:
        import logging

        logging.basicConfig()
        logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)

    def _reencrypt_for_table(table_name, orm_name):
        table_for_select = sqlalchemy.Table(
            table_name,
            sqlalchemy.MetaData(),
            Column("id", key_type(orm_name), primary_key=True),
            Column(
                "encrypted_options",
                ConfigurationContainer.as_mutable(
                    EncryptedConfiguration(db.Text, old_secret, FernetEngine)
                ),
            ),
        )
        table_for_update = sqlalchemy.Table(
            table_name,
            sqlalchemy.MetaData(),
            Column("id", key_type(orm_name), primary_key=True),
            Column(
                "encrypted_options",
                ConfigurationContainer.as_mutable(
                    EncryptedConfiguration(db.Text, new_secret, FernetEngine)
                ),
            ),
        )

        update = table_for_update.update()
        selected_items = db.session.execute(select([table_for_select]))
        for item in selected_items:
            stmt = update.where(table_for_update.c.id == item["id"]).values(
                encrypted_options=item["encrypted_options"]
            )
            db.session.execute(stmt)

        selected_items.close()
        db.session.commit()

    _reencrypt_for_table("data_sources", "DataSource")
    _reencrypt_for_table("notification_destinations", "NotificationDestination")
