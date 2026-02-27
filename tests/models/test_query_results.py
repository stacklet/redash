import datetime
from unittest.mock import MagicMock, patch

from redash import models
from redash.utils import utcnow
from tests import BaseTestCase


class QueryResultTest(BaseTestCase):
    def test_get_latest_returns_none_if_not_found(self):
        found_query_result = models.QueryResult.get_latest(self.factory.data_source, "SELECT 1", 60)
        self.assertIsNone(found_query_result)

    def test_get_latest_returns_when_found(self):
        qr = self.factory.create_query_result()
        found_query_result = models.QueryResult.get_latest(qr.data_source, qr.query_text, 60)

        self.assertEqual(qr, found_query_result)

    def test_get_latest_doesnt_return_query_from_different_data_source(self):
        qr = self.factory.create_query_result()
        data_source = self.factory.create_data_source()
        found_query_result = models.QueryResult.get_latest(data_source, qr.query_text, 60)

        self.assertIsNone(found_query_result)

    def test_get_latest_doesnt_return_if_ttl_expired(self):
        yesterday = utcnow() - datetime.timedelta(days=1)
        qr = self.factory.create_query_result(retrieved_at=yesterday)

        found_query_result = models.QueryResult.get_latest(qr.data_source, qr.query_text, max_age=60)

        self.assertIsNone(found_query_result)

    def test_get_latest_returns_if_ttl_not_expired(self):
        yesterday = utcnow() - datetime.timedelta(seconds=30)
        qr = self.factory.create_query_result(retrieved_at=yesterday)

        found_query_result = models.QueryResult.get_latest(qr.data_source, qr.query_text, max_age=120)

        self.assertEqual(found_query_result, qr)

    def test_get_latest_returns_the_most_recent_result(self):
        yesterday = utcnow() - datetime.timedelta(seconds=30)
        self.factory.create_query_result(retrieved_at=yesterday)
        qr = self.factory.create_query_result()

        found_query_result = models.QueryResult.get_latest(qr.data_source, qr.query_text, 60)

        self.assertEqual(found_query_result.id, qr.id)

    def test_prefilter_preserves_limit_and_offset_for_db_role_user(self):
        """
        Verify that prefilter_query_results correctly saves and restores
        _limit_clause/_offset_clause when injecting the db_role filter.
        If the save/restore were broken, the limit or offset would be lost
        and the wrong number of rows (or wrong rows) would be returned.
        """
        qr1 = self.factory.create_query_result(db_role="limited")
        qr2 = self.factory.create_query_result(db_role="limited")
        qr3 = self.factory.create_query_result(db_role="limited")
        self.factory.create_query_result()  # no db_role — must be excluded

        mock_user = MagicMock()
        mock_user.db_role = "limited"

        with patch("redash.models.current_user", mock_user):
            results = (
                models.QueryResult.query.order_by(models.QueryResult.id)
                .limit(2)
                .offset(1)
                .all()
            )

        # limit=2 must be preserved — 3 limited rows exist but only 2 returned
        self.assertEqual(len(results), 2)
        # offset=1 must be preserved — qr1 is skipped, qr2 and qr3 returned
        self.assertNotEqual(results[0].id, qr1.id)
        self.assertEqual(results[0].id, qr2.id)
        self.assertEqual(results[1].id, qr3.id)
        # db_role filter must still be applied
        self.assertTrue(all(r.db_role == "limited" for r in results))

    def test_get_latest_returns_results_per_db_role(self):
        before = utcnow() - datetime.timedelta(seconds=30)
        qr = self.factory.create_query_result(retrieved_at=before)
        limited_role_qr = self.factory.create_query_result(db_role='limited')

        default_role_latest_results = models.QueryResult.get_latest(qr.data_source, qr.query_text, 60)
        limited_role_latest_results = models.QueryResult.get_latest(qr.data_source, qr.query_text, 60, db_role="limited")

        self.assertEqual(qr.id, default_role_latest_results.id)
        self.assertEqual(limited_role_qr.id, limited_role_latest_results.id)

    def test_get_latest_returns_the_last_cached_result_for_negative_ttl(self):
        yesterday = utcnow() + datetime.timedelta(days=-100)
        self.factory.create_query_result(retrieved_at=yesterday)

        yesterday = utcnow() + datetime.timedelta(days=-1)
        qr = self.factory.create_query_result(retrieved_at=yesterday)
        found_query_result = models.QueryResult.get_latest(qr.data_source, qr.query_text, -1)

        self.assertEqual(found_query_result.id, qr.id)

    def test_store_result_does_not_modify_query_update_at(self):
        original_updated_at = utcnow() - datetime.timedelta(hours=1)
        query = self.factory.create_query(updated_at=original_updated_at)

        models.QueryResult.store_result(
            query.org_id,
            query.data_source,
            query.query_hash,
            query.query_text,
            {},
            0,
            utcnow(),
            None,
        )

        self.assertEqual(original_updated_at, query.updated_at)
