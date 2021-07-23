import os
from urllib.parse import urlparse

import boto3
import sqlalchemy

import psycopg2
from psycopg2.extensions import parse_dsn

from redash import settings

DBIAM_USER = os.getenv("REDASH_DBIAM_USER", "")
DBURI_TEMPLATE = os.getenv("REDASH_DATABASE_URL", "")


def get_db_auth_token(username, hostname, port):
    return boto3.client("rds").generate_db_auth_token(
        DBHostname=hostname, Port=port, DBUsername=username
    )


def get_iam_auth_dsn(dburi, dbiam):
    db = urlparse(dburi)
    dsn = parse_dsn(dburi)
    dsn["user"] = dbiam
    dsn["password"] = get_db_auth_token(dbiam, db.hostname, db.port)
    dsn["sslmode"] = "verify-full"
    dsn["sslrootcert"] = "/app/rds-combined-ca-bundle.pem"
    return dsn


def create_do_connect_handler(dburi, dbiam):
    def handler(dialect, conn_rec, cargs, cparams):
        dsn = parse_dsn(dburi)
        dsn = get_iam_auth_dsn(dburi, dbiam)
        print(dsn)
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
    print("found IAM user setting")
    iam_engine = get_db(DBURI_TEMPLATE, DBIAM_USER)

    username = redash_engine.url.username
    password = redash_engine.url.password

    with iam_engine.connect() as conn:
        print(f"creating schema {settings.SQLALCHEMY_DATABASE_SCHEMA}")
        conn.execute(
            f"CREATE SCHEMA IF NOT EXISTS {settings.SQLALCHEMY_DATABASE_SCHEMA}"
        )
        result = conn.execute(f"SELECT 1 FROM pg_roles WHERE rolname='{username}'")
        if not result.fetchone():
            print(f"creating user {username}")
            conn.execute(f"CREATE ROLE {username} WITH PASSWORD '{password}' LOGIN")
        print(
            f"granting all privileges on schema, tables, sequences in {settings.SQLALCHEMY_DATABASE_SCHEMA} for {username}"
        )
        conn.execute(
            f"GRANT ALL PRIVILEGES ON SCHEMA {settings.SQLALCHEMY_DATABASE_SCHEMA} TO {username}"
        )
        conn.execute(
            f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA {settings.SQLALCHEMY_DATABASE_SCHEMA} TO {username}"
        )
        conn.execute(
            f"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {settings.SQLALCHEMY_DATABASE_SCHEMA} TO {username}"
        )