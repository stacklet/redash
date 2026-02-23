import datetime

from unittest.mock import patch

from redash import models
from redash.tasks.queries.maintenance import cleanup_query_results
from redash.utils import utcnow
from tests import BaseTestCase


TWO_WEEKS_AGO = utcnow() - datetime.timedelta(days=14)


def _exists(qr_id):
    """Check DB directly, bypassing the session identity map."""
    return (
        models.QueryResult.query.filter(models.QueryResult.id == qr_id).count() == 1
    )


class TestCleanupQueryResults(BaseTestCase):
    """
    Integration tests for cleanup_query_results() that exercise the full
    DELETE ... WHERE id IN (subquery) path against the database.

    The unit tests for QueryResult.unused() in test_models.py verify the
    filtering logic; these tests verify that the task actually executes
    without error and produces the correct database changes.
    """

    def test_deletes_old_unused_results(self):
        """Old query results with no referencing query are deleted."""
        qr = self.factory.create_query_result(retrieved_at=TWO_WEEKS_AGO)
        models.db.session.commit()

        cleanup_query_results()

        self.assertFalse(_exists(qr.id))

    def test_does_not_delete_results_still_referenced_by_query(self):
        """Query results that are a query's latest_query_data are not deleted."""
        qr = self.factory.create_query_result(retrieved_at=TWO_WEEKS_AGO)
        self.factory.create_query(latest_query_data=qr)
        models.db.session.commit()

        cleanup_query_results()

        self.assertTrue(_exists(qr.id))

    def test_does_not_delete_recent_unused_results(self):
        """Unused query results newer than the age threshold are not deleted."""
        qr = self.factory.create_query_result()  # retrieved_at defaults to now
        models.db.session.commit()

        cleanup_query_results()

        self.assertTrue(_exists(qr.id))

    def test_respects_cleanup_count_limit(self):
        """At most QUERY_RESULTS_CLEANUP_COUNT results are deleted per run."""
        for _ in range(5):
            self.factory.create_query_result(retrieved_at=TWO_WEEKS_AGO)
        models.db.session.commit()

        with patch("redash.tasks.queries.maintenance.settings") as mock_settings:
            mock_settings.QUERY_RESULTS_CLEANUP_COUNT = 3
            mock_settings.QUERY_RESULTS_CLEANUP_MAX_AGE = 7
            cleanup_query_results()

        remaining = models.QueryResult.query.filter(
            models.QueryResult.retrieved_at == TWO_WEEKS_AGO
        ).count()
        self.assertEqual(remaining, 2)

    def test_deletes_multiple_old_unused_results(self):
        """All old unused results within the batch limit are deleted."""
        qr1 = self.factory.create_query_result(retrieved_at=TWO_WEEKS_AGO)
        qr2 = self.factory.create_query_result(retrieved_at=TWO_WEEKS_AGO)
        models.db.session.commit()

        cleanup_query_results()

        self.assertFalse(_exists(qr1.id))
        self.assertFalse(_exists(qr2.id))
