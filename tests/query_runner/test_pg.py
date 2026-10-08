from unittest import TestCase
from unittest.mock import patch

from redash.query_runner.pg import PostgreSQL, build_schema


class TestBuildSchema(TestCase):
    def test_handles_dups_between_public_and_other_schemas(self):
        results = {
            "rows": [
                {
                    "table_schema": "public",
                    "table_name": "main.users",
                    "column_name": "id",
                },
                {"table_schema": "main", "table_name": "users", "column_name": "id"},
                {"table_schema": "main", "table_name": "users", "column_name": "name"},
            ]
        }

        schema = {}

        build_schema(results, schema)

        self.assertIn("main.users", schema.keys())
        self.assertListEqual(schema["main.users"]["columns"], ["id", "name"])
        self.assertIn('public."main.users"', schema.keys())
        self.assertListEqual(schema['public."main.users"']["columns"], ["id"])

    def test_build_schema_with_data_types(self):
        results = {
            "rows": [
                {"table_schema": "main", "table_name": "users", "column_name": "id", "data_type": "integer"},
                {"table_schema": "main", "table_name": "users", "column_name": "name", "data_type": "varchar"},
            ]
        }

        schema = {}

        build_schema(results, schema)

        self.assertListEqual(
            schema["main.users"]["columns"], [{"name": "id", "type": "integer"}, {"name": "name", "type": "varchar"}]
        )


class TestGenRolePass(TestCase):
    # The same vector is pinned against stacklet.shared.sql.rls.gen_role_pass in the
    # platform; the two must derive identical passwords.
    ROLE = "sso_alice_at_example_com_a1b2c3"
    SECRET = "rls-test-secret"
    EXPECTED = "30f1f1a4d09bae826d882a048b1ea7bcc6354e710dd4d7faf4aefd55e07913c9"

    def setUp(self):
        self.runner = PostgreSQL({})

    def test_matches_platform_vector(self):
        with patch("redash.settings.RLS_SECRET", self.SECRET):
            self.assertEqual(self.runner._gen_role_pass(self.ROLE), self.EXPECTED)

    def test_ignores_datasource_secret_key(self):
        with (
            patch("redash.settings.RLS_SECRET", self.SECRET),
            patch("redash.settings.DATASOURCE_SECRET_KEY", "something-else"),
        ):
            self.assertEqual(self.runner._gen_role_pass(self.ROLE), self.EXPECTED)

    def test_unset_secret_raises(self):
        with patch("redash.settings.RLS_SECRET", None):
            with self.assertRaisesRegex(ValueError, "REDASH_RLS_SECRET"):
                self.runner._gen_role_pass(self.ROLE)
