from mock import ANY, patch
from sqlalchemy import select

from redash.metrics.database import _table_name_from_select_element
from redash.models import Query, User
from tests import BaseTestCase


class TestTableNameExtraction(BaseTestCase):
    """Test _table_name_from_select_element function with various query types."""

    def test_simple_select(self):
        """Test table name extraction from a simple SELECT query."""
        query = select(Query.__table__.c.id)
        table_name = _table_name_from_select_element(query)
        self.assertEqual(table_name, "queries")

    def test_select_from_subquery(self):
        """Test table name extraction from a query with a subquery (Alias)."""
        # Create a subquery - this is what's failing in the e2e tests
        subquery = select(Query.__table__.c.id).subquery()
        query = select(subquery.c.id)

        # This should extract the table name from inside the subquery
        table_name = _table_name_from_select_element(query)
        self.assertEqual(table_name, "queries")

    def test_select_from_join(self):
        """Test table name extraction from a query with a join."""
        queries_table = Query.__table__
        users_table = User.__table__

        query = select(queries_table.c.id).select_from(
            queries_table.join(users_table, queries_table.c.user_id == users_table.c.id)
        )

        # Should extract the left table from the join
        table_name = _table_name_from_select_element(query)
        self.assertEqual(table_name, "queries")

    def test_select_from_table_alias(self):
        """Test table name extraction from a query with a table alias."""
        aliased = Query.__table__.alias('q')
        query = select(aliased.c.id)

        # Should extract the original table name
        table_name = _table_name_from_select_element(query)
        self.assertEqual(table_name, "queries")


@patch("statsd.StatsClient.timing")
class TestDatabaseMetrics(BaseTestCase):
    def test_db_request_records_statsd_metrics(self, timing):
        self.factory.create_query()
        timing.assert_called_with("db.changes.insert", ANY)
