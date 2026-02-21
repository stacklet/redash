"""Tests for redash.utils.query_order — focusing on get_query_entities and
the _flatten_joins helper that was added to fix nested-join unwrapping."""

from unittest.mock import patch

from tests import BaseTestCase
from redash.models import Dashboard, Query, QueryResult, User, db
from redash.utils.query_order import _flatten_joins, get_query_entities, get_query_entity_by_alias


class TestGetQueryEntityByAlias(BaseTestCase):
    """Tests for get_query_entity_by_alias, particularly the empty-entities guard."""

    def test_returns_none_when_no_alias_and_entities_empty(self):
        """When alias is falsy and get_query_entities returns [], return None not IndexError."""
        q = db.session.query(Query)
        with patch("redash.utils.query_order.get_query_entities", return_value=[]):
            result = get_query_entity_by_alias(q, None)
        self.assertIsNone(result)

    def test_returns_first_entity_when_no_alias(self):
        """When alias is falsy and entities exist, return the first one."""
        q = db.session.query(Query)
        result = get_query_entity_by_alias(q, None)
        self.assertIs(result, Query)

    def test_returns_none_when_alias_not_found(self):
        """When alias does not match any entity, return None."""
        q = db.session.query(Query)
        result = get_query_entity_by_alias(q, "nonexistent_table")
        self.assertIsNone(result)


class TestFlattenJoins(BaseTestCase):
    """Unit tests for _flatten_joins independent of any ORM query."""

    def _make_join(self, left, right):
        """Build a SQLAlchemy Join from two table expressions."""
        import sqlalchemy as sa
        return left.join(right, left.c.id == right.c.id, isouter=True)

    def test_non_join_passthrough(self):
        """Plain tables are returned unchanged."""
        t = Query.__table__
        result = _flatten_joins([t])
        self.assertEqual(result, [t])

    def test_empty_list(self):
        result = _flatten_joins([])
        self.assertEqual(result, [])

    def test_two_table_join(self):
        """A single Join of (A, B) yields [A_table, B_table]."""
        a = Query.__table__
        b = User.__table__
        join = a.join(b, a.c.user_id == b.c.id, isouter=True)
        result = _flatten_joins([join])
        self.assertIn(a, result)
        self.assertIn(b, result)
        self.assertEqual(len(result), 2)

    def test_three_table_nested_join(self):
        """A three-way join ((A JOIN B) JOIN C) yields all three tables.

        This is the case the old single-level loop missed: the left side of
        the outer join is itself a Join, not a Table.
        """
        a = Query.__table__
        b = User.__table__
        c = QueryResult.__table__

        inner = a.join(b, a.c.user_id == b.c.id, isouter=True)
        outer = inner.join(c, c.c.id == a.c.latest_query_data_id, isouter=True)

        result = _flatten_joins([outer])

        self.assertIn(a, result)
        self.assertIn(b, result)
        self.assertIn(c, result)
        self.assertEqual(len(result), 3)

    def test_four_table_deeply_nested_join(self):
        """Four-table join is fully unwrapped (three levels deep)."""
        a = Query.__table__
        b = User.__table__
        c = QueryResult.__table__
        d = Dashboard.__table__

        ab = a.join(b, a.c.user_id == b.c.id, isouter=True)
        abc = ab.join(c, c.c.id == a.c.latest_query_data_id, isouter=True)
        abcd = abc.join(d, d.c.user_id == b.c.id, isouter=True)

        result = _flatten_joins([abcd])

        self.assertIn(a, result)
        self.assertIn(b, result)
        self.assertIn(c, result)
        self.assertIn(d, result)
        self.assertEqual(len(result), 4)

    def test_multiple_independent_froms(self):
        """Multiple non-joined FROM items are all returned."""
        a = Query.__table__
        b = User.__table__
        result = _flatten_joins([a, b])
        self.assertIn(a, result)
        self.assertIn(b, result)
        self.assertEqual(len(result), 2)


class TestGetQueryEntitiesJoins(BaseTestCase):
    """Integration tests: get_query_entities extracts correct ORM classes from
    queries with explicit joins, including three-way joins."""

    def test_single_entity(self):
        q = db.session.query(Query)
        entities = get_query_entities(q)
        self.assertIn(Query, entities)

    def test_two_table_join_returns_both_entities(self):
        q = db.session.query(Query).join(User, User.id == Query.user_id)
        entities = get_query_entities(q)
        self.assertIn(Query, entities)
        self.assertIn(User, entities)

    def test_three_table_join_returns_all_entities(self):
        """The nested-join fix: all three ORM classes must appear.

        Before _flatten_joins was introduced, the left-side join node was
        returned as a raw Join object rather than being unwrapped, so the
        inner tables (here: Query and User) were dropped from the result.
        """
        q = (
            db.session.query(Query)
            .join(User, User.id == Query.user_id)
            .join(QueryResult, QueryResult.id == Query.latest_query_data_id)
        )
        entities = get_query_entities(q)
        self.assertIn(Query, entities)
        self.assertIn(User, entities)
        self.assertIn(QueryResult, entities)
