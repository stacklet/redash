"""Tests for Stacklet's Flask-SQLAlchemy engine creation override."""

from unittest import mock

import sqlalchemy
from flask import Flask

from redash.models.base import RedashSQLAlchemy


class TestRedashSQLAlchemyEngineOverride:
    """Test the _make_engine override for Flask-SQLAlchemy 3.x compatibility."""

    @mock.patch("redash.models.base.get_env_db")
    def test_uses_custom_engine_when_get_env_db_returns_engine(self, mock_get_env_db):
        """Should return custom engine from get_env_db() when available."""
        # Create mock custom engine
        mock_engine = mock.Mock(spec=sqlalchemy.engine.Engine)
        mock_get_env_db.return_value = mock_engine

        # Create Flask app and db instance
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///postgres"
        db = RedashSQLAlchemy()

        # Call _make_engine directly (Flask-SQLAlchemy 3.x internal method)
        result = db._make_engine(
            bind_key=None,
            options={"url": "postgresql://localhost/testdb"},
            app=app
        )

        assert result is mock_engine
        mock_get_env_db.assert_called_once()

    @mock.patch("redash.models.base.get_env_db")
    def test_falls_back_to_default_when_get_env_db_returns_none(self, mock_get_env_db):
        """Should use default Flask-SQLAlchemy engine creation when get_env_db() returns None."""
        mock_get_env_db.return_value = None

        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/testdb"
        db = RedashSQLAlchemy()

        # This should fall back to the parent class implementation
        result = db._make_engine(
            bind_key=None,
            options={"url": "postgresql://localhost/testdb"},
            app=app
        )

        # Should have called get_env_db to check for custom engine
        mock_get_env_db.assert_called_once()
        # Should return an engine (from parent implementation)
        assert result is not None
        assert isinstance(result, sqlalchemy.engine.Engine)

    @mock.patch.dict("os.environ", {
        "ASSETDB_DATABASE_URI": "postgresql://{user}:{password}@testhost:5432/assetdb",
        "ASSETDB_DBCRED_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:creds",
        "SQLALCHEMY_DB_SCHEMA": "redash"
    })
    @mock.patch("redash.stacklet.auth.get_db_cred_secret")
    def test_integration_with_flask_app_initialization(self, mock_get_secret):
        """Integration test: Flask app init should use custom engine with injected credentials."""
        mock_get_secret.return_value = {"user": "integrationuser", "password": "integrationpass"}

        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///postgres"

        db = RedashSQLAlchemy()
        db.init_app(app)

        # Flask-SQLAlchemy 3.x creates engines immediately during init_app
        with app.app_context():
            engine = db.engine
            assert engine is not None
            # Verify custom engine was used with credentials from Secrets Manager
            assert engine.url.username == "integrationuser"
            assert engine.url.password == "integrationpass"
            assert engine.url.host == "testhost"
