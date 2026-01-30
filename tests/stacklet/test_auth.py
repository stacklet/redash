"""Tests for Stacklet database authentication and credential management."""

from unittest import mock

import sqlalchemy

from redash.stacklet.auth import get_db, get_env_db


class TestGetDb:
    """Test database engine creation with Secrets Manager credential injection."""

    def test_returns_none_when_no_uri_provided(self):
        """Should return None when dburi is None."""
        assert get_db(dburi=None) is None

    @mock.patch("redash.stacklet.auth.get_db_cred_secret")
    def test_substitutes_credentials_from_secrets_manager(self, mock_get_secret):
        """Should fetch credentials from AWS Secrets Manager and substitute into URL.

        This tests the SQLAlchemy 2.0 fix: URL.set() instead of direct attribute assignment.
        """
        mock_get_secret.return_value = {"user": "testuser", "password": "testpass123"}

        dburi = "postgresql://{user}:{password}@localhost:5432/testdb"
        dbcreds_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        engine = get_db(dburi=dburi, dbcreds=dbcreds_arn)

        assert engine is not None
        assert isinstance(engine, sqlalchemy.engine.Engine)
        assert engine.url.username == "testuser"
        assert engine.url.password == "testpass123"
        assert engine.url.host == "localhost"
        assert engine.url.database == "testdb"

        mock_get_secret.assert_called_once_with(dbcreds_arn)

    def test_creates_engine_without_credential_substitution(self):
        """Should create engine directly when no dbcreds ARN provided."""
        dburi = "postgresql://directuser:directpass@localhost:5432/testdb"

        engine = get_db(dburi=dburi, dbcreds=None)

        assert engine is not None
        assert engine.url.username == "directuser"
        # Note: SQLAlchemy 2.0 obscures passwords in URL representation
        assert engine.url.password is not None

    def test_applies_schema_translation(self):
        """Should configure PostgreSQL schema translation when schema parameter provided."""
        dburi = "postgresql://user:pass@localhost:5432/testdb"
        schema = "custom_schema"

        engine = get_db(dburi=dburi, schema=schema)

        # Verify engine was created with schema translation in execution options
        # In SQLAlchemy 2.0, we check the underlying _execution_options dict
        assert hasattr(engine, "_execution_options")
        assert "schema_translate_map" in engine._execution_options
        assert engine._execution_options["schema_translate_map"][None] == schema


class TestGetEnvDb:
    """Test environment-based database configuration."""

    @mock.patch.dict("os.environ", {
        "ASSETDB_DATABASE_URI": "postgresql://{user}:{password}@testhost:5432/assetdb",
        "ASSETDB_DBCRED_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:test",
        "SQLALCHEMY_DB_SCHEMA": "redash"
    })
    @mock.patch("redash.stacklet.auth.get_db_cred_secret")
    def test_reads_configuration_from_environment(self, mock_get_secret):
        """Should read ASSETDB_* environment variables and create engine."""
        mock_get_secret.return_value = {"user": "envuser", "password": "envpass"}

        engine = get_env_db()

        assert engine is not None
        assert engine.url.username == "envuser"
        assert engine.url.password == "envpass"
        assert engine.url.host == "testhost"
        assert engine.url.database == "assetdb"

    @mock.patch.dict("os.environ", {}, clear=True)
    def test_returns_none_without_environment_configuration(self):
        """Should return None when ASSETDB_DATABASE_URI not set."""
        assert get_env_db() is None
