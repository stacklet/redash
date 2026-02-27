"""Tests for custom SQLAlchemy types with SQLAlchemy 2.0 compatibility."""

from datetime import date, datetime, time
from unittest import mock
from unittest.mock import patch

import sqlalchemy.types as sa_types
from sqlalchemy.ext.indexable import index_property

from redash.models.types import EncryptedConfiguration, json_cast_property
from redash.utils.configuration import ConfigurationContainer


class TestEncryptedConfiguration:
    """Test EncryptedConfiguration type with SQLAlchemy 2.0 memoryview handling."""

    def test_process_result_value_converts_memoryview_to_string(self):
        """Should convert memoryview to string for decryption (SQLAlchemy 2.0)."""
        encrypted_type = EncryptedConfiguration()

        # Mock the parent class's process_result_value
        with mock.patch.object(
            encrypted_type.__class__.__bases__[0],
            'process_result_value',
            return_value='{"key": "value"}'
        ) as mock_parent:
            # SQLAlchemy 2.0 returns memoryview for binary columns
            test_string = 'gAAAAABencrypted_base64_data'
            test_data = test_string.encode('utf-8')
            memoryview_data = memoryview(test_data)

            result = encrypted_type.process_result_value(memoryview_data, dialect=None)

            # Verify memoryview was converted to string (parent expects string for .encode())
            call_args = mock_parent.call_args[0]
            assert isinstance(call_args[0], str)
            assert call_args[0] == test_string
            assert isinstance(result, ConfigurationContainer)

    def test_process_result_value_passes_through_strings(self):
        """Should pass string values through unchanged (base64 encoded data)."""
        encrypted_type = EncryptedConfiguration()

        with mock.patch.object(
            encrypted_type.__class__.__bases__[0],
            'process_result_value',
            return_value='{"key": "value"}'
        ) as mock_parent:
            # String values (base64 encoded) should be passed through as-is
            string_value = 'gAAAAABpf9-Iwggh7x5URcMef6tpVFtPb7sHckS4='

            result = encrypted_type.process_result_value(string_value, dialect=None)

            # Verify string was passed through unchanged
            call_args = mock_parent.call_args[0]
            assert call_args[0] == string_value
            assert isinstance(result, ConfigurationContainer)

    def test_process_result_value_handles_none(self):
        """Should handle None values without attempting conversion."""
        encrypted_type = EncryptedConfiguration()

        with mock.patch.object(
            encrypted_type.__class__.__bases__[0],
            'process_result_value',
            return_value=None
        ):
            # None should be passed through unchanged
            result = encrypted_type.process_result_value(None, dialect=None)
            # Result depends on ConfigurationContainer.from_json(None) behavior
            assert result is None or isinstance(result, ConfigurationContainer)


class TestJsonCastPropertyGet:
    """Tests for json_cast_property.__get__ ISO-string-to-type conversion."""

    def _get_with_stored(self, sa_type, stored_value):
        """Exercise __get__ with super().__get__ mocked to return stored_value."""
        prop = json_cast_property(sa_type, "data", "value")
        with patch.object(index_property, "__get__", return_value=stored_value):
            return prop.__get__(object(), type)

    def test_converts_iso_string_to_datetime(self):
        result = self._get_with_stored(sa_types.DateTime(), "2024-01-15T14:30:00")
        assert isinstance(result, datetime)
        assert result == datetime(2024, 1, 15, 14, 30, 0)

    def test_converts_iso_string_to_date(self):
        result = self._get_with_stored(sa_types.Date(), "2024-01-15")
        assert isinstance(result, date)
        assert result == date(2024, 1, 15)

    def test_converts_iso_string_to_time(self):
        result = self._get_with_stored(sa_types.Time(), "14:30:00")
        assert isinstance(result, time)
        assert result == time(14, 30, 0)

    def test_returns_none_unchanged(self):
        result = self._get_with_stored(sa_types.Time(), None)
        assert result is None

    def test_returns_unparseable_string_unchanged(self):
        result = self._get_with_stored(sa_types.Time(), "not-a-time")
        assert result == "not-a-time"


class TestJsonCastPropertySet:
    """Tests for json_cast_property.__set__ type-to-ISO-string serialisation."""

    def _set_and_capture(self, sa_type, value):
        """Call __set__ and capture the value forwarded to super().__set__."""
        prop = json_cast_property(sa_type, "data", "value")
        stored = {}

        def fake_super_set(self_inner, obj, v):
            stored["value"] = v

        with patch.object(index_property, "__set__", fake_super_set):
            prop.__set__(object(), value)
        return stored["value"]

    def test_stores_datetime_as_isoformat(self):
        result = self._set_and_capture(sa_types.DateTime(), datetime(2024, 1, 15, 14, 30, 0))
        assert result == "2024-01-15T14:30:00"

    def test_stores_date_as_isoformat(self):
        result = self._set_and_capture(sa_types.Date(), date(2024, 1, 15))
        assert result == "2024-01-15"

    def test_stores_time_as_isoformat(self):
        result = self._set_and_capture(sa_types.Time(), time(14, 30, 0))
        assert result == "14:30:00"


class TestJsonCastPropertyRoundtrip:
    """Verify __set__ and __get__ are inverses for all three temporal types."""

    def _roundtrip(self, sa_type, value):
        prop = json_cast_property(sa_type, "data", "value")
        stored = {}

        def fake_super_set(self_inner, obj, v):
            stored["value"] = v

        with patch.object(index_property, "__set__", fake_super_set):
            prop.__set__(object(), value)

        with patch.object(index_property, "__get__", return_value=stored["value"]):
            return prop.__get__(object(), type)

    def test_datetime_roundtrip(self):
        original = datetime(2024, 1, 15, 14, 30, 0)
        assert self._roundtrip(sa_types.DateTime(), original) == original

    def test_date_roundtrip(self):
        original = date(2024, 1, 15)
        assert self._roundtrip(sa_types.Date(), original) == original

    def test_time_roundtrip(self):
        original = time(14, 30, 0)
        assert self._roundtrip(sa_types.Time(), original) == original
