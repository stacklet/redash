from unittest import TestCase

import mock
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import NullPool

from redash import settings
from redash.models.base import _engine_options, RedashSQLAlchemy
from redash.models import db
from redash.utils import json_dumps


class TestEngineOptionsJsonSerializer(TestCase):
    def test_json_serializer_always_configured(self):
        """json_serializer must be present in engine_options.

        apply_driver_hacks() was removed in Flask-SQLAlchemy 3.0, so the
        serializer must be set in the engine_options dict passed to the
        constructor rather than in that defunct override.
        """
        self.assertIn("json_serializer", _engine_options)
        self.assertIs(_engine_options["json_serializer"], json_dumps)


class TestMakeEngineNullPool(TestCase):
    def _invoke_make_engine(self, options, disable_pool):
        """Call db._make_engine() with a mocked parent and return the options
        dict as it was seen by the parent (i.e. after in-place modifications)."""
        seen = {}

        def capturing_parent(inner_self, bind_key, opts, app):
            seen.update(opts)
            return mock.MagicMock()

        with mock.patch("redash.models.base.get_env_db", return_value=None):
            with mock.patch.object(settings, "SQLALCHEMY_DISABLE_POOL", disable_pool):
                with mock.patch.object(SQLAlchemy, "_make_engine", capturing_parent):
                    db._make_engine(None, options, None)

        return seen

    def test_pool_options_stripped_when_nullpool(self):
        """Incompatible pool options must be removed before create_engine is
        called with NullPool; passing them causes SQLAlchemy to raise."""
        options = {
            "pool_size": 5,
            "max_overflow": 10,
            "pool_timeout": 30,
            "pool_recycle": 1800,
            "other": "preserved",
        }

        seen = self._invoke_make_engine(options, disable_pool=True)

        self.assertNotIn("pool_size", seen)
        self.assertNotIn("max_overflow", seen)
        self.assertNotIn("pool_timeout", seen)
        self.assertNotIn("pool_recycle", seen)
        self.assertIn("other", seen)

    def test_pool_options_preserved_when_pool_enabled(self):
        """Pool options must pass through unchanged when NullPool is not in use."""
        options = {
            "pool_size": 5,
            "max_overflow": 10,
            "other": "preserved",
        }

        seen = self._invoke_make_engine(options, disable_pool=False)

        self.assertIn("pool_size", seen)
        self.assertIn("max_overflow", seen)
        self.assertIn("other", seen)

    def test_env_engine_returned_without_calling_parent(self):
        """When get_env_db() returns an engine it must be used directly and the
        parent _make_engine must not be called (Stacklet custom connection path)."""
        mock_engine = mock.MagicMock()

        with mock.patch("redash.models.base.get_env_db", return_value=mock_engine):
            with mock.patch.object(SQLAlchemy, "_make_engine") as mock_parent:
                result = db._make_engine(None, {}, None)

        self.assertIs(result, mock_engine)
        mock_parent.assert_not_called()
