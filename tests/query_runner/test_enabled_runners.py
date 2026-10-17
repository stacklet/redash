import importlib
import importlib.util
from unittest import TestCase, skipUnless

from redash import settings
from redash.query_runner import query_runners

# Query runners disable themselves when their driver fails to import, so a
# dependency bump that breaks a driver would otherwise go unnoticed. The check
# needs the optional all_ds dependency group, detected here via pyathena.
ALL_DS_INSTALLED = importlib.util.find_spec("pyathena") is not None

# Default runners not expected to register in the CI image.
KNOWN_DISABLED = {
    "redash.query_runner.db2",  # ibm_db is not a dependency
}


@skipUnless(ALL_DS_INSTALLED, "all_ds dependency group not installed")
class TestEnabledQueryRunners(TestCase):
    def test_default_query_runners_register(self):
        for module in settings.default_query_runners:
            importlib.import_module(module)
        registered = {runner.__module__ for runner in query_runners.values()}
        disabled = set(settings.default_query_runners) - registered
        self.assertEqual(disabled, KNOWN_DISABLED)
