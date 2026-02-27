from unittest import TestCase

from mock import MagicMock
from werkzeug.exceptions import BadRequest

from redash.handlers.base import paginate


class DummyResults:
    items = [i for i in range(25)]


dummy_results = DummyResults()


class TestPaginate(TestCase):
    def setUp(self):
        self.query_set = MagicMock()
        self.query_set.count = MagicMock(return_value=102)
        self.query_set.paginate = MagicMock(return_value=dummy_results)

    def test_returns_paginated_results(self):
        page = paginate(self.query_set, 1, 25, lambda x: x)
        self.assertEqual(page["page"], 1)
        self.assertEqual(page["page_size"], 25)
        self.assertEqual(page["count"], 102)
        self.assertEqual(page["results"], dummy_results.items)

    def test_raises_error_for_bad_page(self):
        self.assertRaises(BadRequest, lambda: paginate(self.query_set, -1, 25, lambda x: x))
        self.assertRaises(BadRequest, lambda: paginate(self.query_set, 6, 25, lambda x: x))

    def test_raises_error_for_bad_page_size(self):
        self.assertRaises(BadRequest, lambda: paginate(self.query_set, 1, 251, lambda x: x))
        self.assertRaises(BadRequest, lambda: paginate(self.query_set, 1, -1, lambda x: x))

    def test_page_size_above_100_not_silently_capped(self):
        # Sizes 101-250 are valid but were previously silently capped to 100
        # by Flask-SQLAlchemy's default max_per_page. Verify paginate() is
        # called with max_per_page=page_size so the full requested size is used.
        for page_size in (101, 150, 250):
            self.query_set.reset_mock()
            paginate(self.query_set, 1, page_size, lambda x: x)
            self.query_set.paginate.assert_called_once_with(
                page=1, per_page=page_size, max_per_page=page_size
            )
