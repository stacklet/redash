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
import psycopg2
from psycopg2.extensions import parse_dsn

from redash import settings
from redash.models.base import Column, key_type
from redash.models.types import EncryptedConfiguration
from redash.utils.configuration import ConfigurationContainer

manager = AppGroup(help="Manage the database (create/drop tables. reencrypt data.).")

DBIAM_USER = "assetdb"  # os.environ["REDASH_DBIAM_USER"]
DBURI_TEMPLATE = "postgresql://{user}:{password}@assetdb.csowsmcthnij.us-east-2.rds.amazonaws.com:5432/assetdb"  # os.environ["REDASH_DATABASE_URL"]


def get_db_auth_token(username, hostname, port):
    return boto3.client("rds").generate_db_auth_token(
        DBHostname=hostname, Port=port, DBUsername=username
    )


def get_iam_auth_dsn(dburi, dbiam):
    db = urlparse(dburi)
    dsn = parse_dsn(dburi)
    dsn["user"] = dbiam
    dsn["password"] = get_db_auth_token(dbiam, db.hostname, db.port)
    # dsn["sslmode"] = "prefer"
    # dsn["sslrootcert"] = "/src/stacklet/assetdb/files/aws/rds-combined-ca-bundle.pem"
    return dsn


def create_do_connect_handler(dburi, dbiam):
    def handler(dialect, conn_rec, cargs, cparams):
        dsn = parse_dsn(dburi)
        dsn = get_iam_auth_dsn(dburi, dbiam)
        return psycopg2.connect(**dsn)

    return handler


def get_db(dburi, dbiam):
    if "postgresql" in dburi:
        engine = sqlalchemy.create_engine("postgresql://")
        sqlalchemy.event.listen(
            engine, "do_connect", create_do_connect_handler(dburi, dbiam)
        )
        return engine

    engine = sqlalchemy.create_engine(dburi)
    return engine


def redash_user_grant(redash_engine):
    iam_engine = get_db(DBURI_TEMPLATE, DBIAM_USER)
    print(iam_engine.url)

    username = redash_engine.url.username
    password = redash_engine.url.password

    with iam_engine.connect() as conn:
        conn.execute(
            f"CREATE SCHEMA IF NOT EXISTS {settings.SQLALCHEMY_DATABASE_SCHEMA}"
        )
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

    redash_user_grant(db.engine)

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
