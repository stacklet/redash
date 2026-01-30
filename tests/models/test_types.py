"""Tests for custom SQLAlchemy types with SQLAlchemy 2.0 compatibility."""

from unittest import mock

from redash.models.types import EncryptedConfiguration
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
