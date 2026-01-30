import textwrap

import mock
import sqlalchemy
from click.testing import CliRunner
from sqlalchemy.exc import DatabaseError
from sqlalchemy.sql import text

from redash import settings
from redash.cli import manager
from redash.cli.database import _wait_for_db_connection, is_db_empty, load_extensions
from redash.models import DataSource, Group, Organization, User, db
from redash.query_runner import query_runners
from redash.utils.configuration import ConfigurationContainer
from tests import BaseTestCase


class DataSourceCommandTests(BaseTestCase):
    def test_interactive_new(self):
        runner = CliRunner()
        pg_i = list(query_runners.keys()).index("pg") + 1
        result = runner.invoke(
            manager,
            ["ds", "new"],
            input="test\n%s\n\n\nexample.com\n\n\ntestdb\n" % (pg_i,),
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(DataSource.query.count(), 1)
        ds = DataSource.query.first()
        self.assertEqual(ds.name, "test")
        self.assertEqual(ds.type, "pg")
        self.assertEqual(ds.options["dbname"], "testdb")

    def test_options_new(self):
        runner = CliRunner()
        result = runner.invoke(
            manager,
            [
                "ds",
                "new",
                "test",
                "--options",
                '{"host": "example.com", "dbname": "testdb"}',
                "--type",
                "pg",
            ],
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(DataSource.query.count(), 1)
        ds = DataSource.query.first()
        self.assertEqual(ds.name, "test")
        self.assertEqual(ds.type, "pg")
        self.assertEqual(ds.options["host"], "example.com")
        self.assertEqual(ds.options["dbname"], "testdb")

    def test_bad_type_new(self):
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "new", "test", "--type", "wrong"])
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not supported", result.output)
        self.assertEqual(DataSource.query.count(), 0)

    def test_bad_options_new(self):
        runner = CliRunner()
        result = runner.invoke(
            manager,
            [
                "ds",
                "new",
                "test",
                "--options",
                '{"host": 12345, "dbname": "testdb"}',
                "--type",
                "pg",
            ],
        )
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("invalid configuration", result.output)
        self.assertEqual(DataSource.query.count(), 0)

    def test_list(self):
        self.factory.create_data_source(
            name="test1",
            type="pg",
            options=ConfigurationContainer({"host": "example.com", "dbname": "testdb1"}),
        )
        self.factory.create_data_source(
            name="test2",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )

        self.factory.create_data_source(
            name="Atest",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "list"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        expected_output = """
        Id: 3
        Name: Atest
        Type: sqlite
        Options: {"dbpath": "/tmp/test.db"}
        --------------------
        Id: 1
        Name: test1
        Type: pg
        Options: {"dbname": "testdb1", "host": "example.com"}
        --------------------
        Id: 2
        Name: test2
        Type: sqlite
        Options: {"dbpath": "/tmp/test.db"}
        """
        self.assertMultiLineEqual(result.output, textwrap.dedent(expected_output).lstrip())

    def test_connection_test(self):
        self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "test", "test1"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Success", result.output)

    def test_connection_bad_test(self):
        self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/notexist.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "test", "test1"])
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Failure", result.output)

    def test_connection_delete(self):
        self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "delete", "test1"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Deleting", result.output)
        self.assertEqual(DataSource.query.count(), 0)

    def test_connection_bad_delete(self):
        self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "delete", "wrong"])
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Couldn't find", result.output)
        self.assertEqual(DataSource.query.count(), 1)

    def test_options_edit(self):
        self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(
            manager,
            [
                "ds",
                "edit",
                "test1",
                "--options",
                '{"host": "example.com", "dbname": "testdb"}',
                "--name",
                "test2",
                "--type",
                "pg",
            ],
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(DataSource.query.count(), 1)
        ds = DataSource.query.first()
        self.assertEqual(ds.name, "test2")
        self.assertEqual(ds.type, "pg")
        self.assertEqual(ds.options["host"], "example.com")
        self.assertEqual(ds.options["dbname"], "testdb")

    def test_bad_type_edit(self):
        self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["ds", "edit", "test", "--type", "wrong"])
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not supported", result.output)
        ds = DataSource.query.first()
        self.assertEqual(ds.type, "sqlite")

    def test_bad_options_edit(self):
        ds = self.factory.create_data_source(
            name="test1",
            type="sqlite",
            options=ConfigurationContainer({"dbpath": "/tmp/test.db"}),
        )
        runner = CliRunner()
        result = runner.invoke(
            manager,
            [
                "ds",
                "new",
                "test",
                "--options",
                '{"host": 12345, "dbname": "testdb"}',
                "--type",
                "pg",
            ],
        )
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("invalid configuration", result.output)
        ds = DataSource.query.first()
        self.assertEqual(ds.type, "sqlite")
        self.assertEqual(ds.options._config, {"dbpath": "/tmp/test.db"})


class GroupCommandTests(BaseTestCase):
    def test_create(self):
        gcount = Group.query.count()
        perms = ["create_query", "edit_query", "view_query"]
        runner = CliRunner()
        result = runner.invoke(manager, ["groups", "create", "test", "--permissions", ",".join(perms)])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(Group.query.count(), gcount + 1)
        g = Group.query.order_by(Group.id.desc()).first()
        db.session.add(self.factory.org)
        self.assertEqual(g.org_id, self.factory.org.id)
        self.assertEqual(g.permissions, perms)

    def test_change_permissions(self):
        g = self.factory.create_group(permissions=["list_dashboards"])
        db.session.commit()
        g_id = g.id
        perms = ["create_query", "edit_query", "view_query"]
        runner = CliRunner()
        result = runner.invoke(
            manager,
            [
                "groups",
                "change_permissions",
                str(g_id),
                "--permissions",
                ",".join(perms),
            ],
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        g = Group.query.filter(Group.id == g_id).first()
        self.assertEqual(g.permissions, perms)

    def test_list(self):
        self.factory.create_group(name="test", permissions=["list_dashboards"])
        self.factory.create_group(name="agroup", permissions=["list_dashboards"])
        self.factory.create_group(name="bgroup", permissions=["list_dashboards"])

        self.factory.create_user(
            name="Fred Foobar",
            email="foobar@example.com",
            org=self.factory.org,
            group_ids=[self.factory.default_group.id],
        )

        runner = CliRunner()
        result = runner.invoke(manager, ["groups", "list"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        output = """
        Id: 1
        Name: admin
        Type: builtin
        Organization: default
        Permissions: [admin,super_admin]
        Users:
        --------------------
        Id: 4
        Name: agroup
        Type: regular
        Organization: default
        Permissions: [list_dashboards]
        Users:
        --------------------
        Id: 5
        Name: bgroup
        Type: regular
        Organization: default
        Permissions: [list_dashboards]
        Users:
        --------------------
        Id: 2
        Name: default
        Type: builtin
        Organization: default
        Permissions: [create_dashboard,create_query,edit_dashboard,edit_query,view_query,view_source,execute_query,list_users,schedule_query,list_dashboards,list_alerts,list_data_sources]
        Users: Fred Foobar
        --------------------
        Id: 3
        Name: test
        Type: regular
        Organization: default
        Permissions: [list_dashboards]
        Users:
        """
        self.assertMultiLineEqual(result.output, textwrap.dedent(output).lstrip())


class OrganizationCommandTests(BaseTestCase):
    def test_set_google_apps_domains(self):
        domains = ["example.org", "example.com"]
        runner = CliRunner()
        result = runner.invoke(manager, ["org", "set_google_apps_domains", ",".join(domains)])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        db.session.add(self.factory.org)
        self.assertEqual(self.factory.org.google_apps_domains, domains)

    def test_show_google_apps_domains(self):
        # Re-add org to session since it may have been detached
        db.session.add(self.factory.org)
        self.factory.org.settings[Organization.SETTING_GOOGLE_APPS_DOMAINS] = [
            "example.org",
            "example.com",
        ]
        db.session.commit()
        runner = CliRunner()
        result = runner.invoke(manager, ["org", "show_google_apps_domains"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        output = """
        Current list of Google Apps domains: example.org, example.com
        """
        self.assertMultiLineEqual(result.output, textwrap.dedent(output).lstrip())

    def test_create(self):
        runner = CliRunner()
        result = runner.invoke(manager, ["org", "create", "test", "--slug", "test"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)

        ucount = Organization.query.count()

        self.assertEqual(ucount, 2)

    def test_list(self):
        self.factory.create_org(name="test", slug="test_org")
        self.factory.create_org(name="Borg", slug="B_org")
        self.factory.create_org(name="Aorg", slug="A_org")
        runner = CliRunner()
        result = runner.invoke(manager, ["org", "list"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        output = """
        Id: 4
        Name: Aorg
        Slug: A_org
        --------------------
        Id: 3
        Name: Borg
        Slug: B_org
        --------------------
        Id: 1
        Name: Default
        Slug: default
        --------------------
        Id: 2
        Name: test
        Slug: test_org
        """
        self.assertMultiLineEqual(result.output, textwrap.dedent(output).lstrip())


class UserCommandTests(BaseTestCase):
    def test_create_basic(self):
        runner = CliRunner()
        result = runner.invoke(
            manager,
            ["users", "create", "foobar@example.com", "Fred Foobar"],
            input="password1\npassword1\n",
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        u = User.query.filter(User.email == "foobar@example.com").first()
        self.assertEqual(u.name, "Fred Foobar")
        self.assertTrue(u.verify_password("password1"))
        self.assertEqual(u.group_ids, [u.org.default_group.id])

    def test_create_admin(self):
        runner = CliRunner()
        result = runner.invoke(
            manager,
            [
                "users",
                "create",
                "foobar@example.com",
                "Fred Foobar",
                "--password",
                "password1",
                "--admin",
            ],
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        u = User.query.filter(User.email == "foobar@example.com").first()
        self.assertEqual(u.name, "Fred Foobar")
        self.assertTrue(u.verify_password("password1"))
        self.assertEqual(u.group_ids, [u.org.default_group.id, u.org.admin_group.id])

    def test_create_googleauth(self):
        runner = CliRunner()
        result = runner.invoke(
            manager,
            ["users", "create", "foobar@example.com", "Fred Foobar", "--google"],
        )
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        u = User.query.filter(User.email == "foobar@example.com").first()
        self.assertEqual(u.name, "Fred Foobar")
        self.assertIsNone(u.password_hash)
        self.assertEqual(u.group_ids, [u.org.default_group.id])

    def test_create_bad(self):
        self.factory.create_user(email="foobar@example.com")
        runner = CliRunner()
        result = runner.invoke(
            manager,
            ["users", "create", "foobar@example.com", "Fred Foobar"],
            input="password1\npassword1\n",
        )
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Failed", result.output)

    def test_delete(self):
        self.factory.create_user(email="foobar@example.com")
        ucount = User.query.count()
        runner = CliRunner()
        result = runner.invoke(manager, ["users", "delete", "foobar@example.com"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(User.query.filter(User.email == "foobar@example.com").count(), 0)
        self.assertEqual(User.query.count(), ucount - 1)

    def test_delete_bad(self):
        ucount = User.query.count()
        runner = CliRunner()
        result = runner.invoke(manager, ["users", "delete", "foobar@example.com"])
        self.assertIn("Deleted 0 users", result.output)
        self.assertEqual(User.query.count(), ucount)

    def test_password(self):
        self.factory.create_user(email="foobar@example.com")
        runner = CliRunner()
        result = runner.invoke(manager, ["users", "password", "foobar@example.com", "xyzzy"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        u = User.query.filter(User.email == "foobar@example.com").first()
        self.assertTrue(u.verify_password("xyzzy"))

    def test_password_bad(self):
        runner = CliRunner()
        result = runner.invoke(manager, ["users", "password", "foobar@example.com", "xyzzy"])
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not found", result.output)

    def test_password_bad_org(self):
        runner = CliRunner()
        result = runner.invoke(
            manager,
            ["users", "password", "foobar@example.com", "xyzzy", "--org", "default"],
        )
        self.assertTrue(result.exception)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not found", result.output)

    def test_invite(self):
        admin = self.factory.create_user(email="redash-admin@example.com")
        runner = CliRunner()
        with mock.patch("redash.cli.users.invite_user") as iu:
            result = runner.invoke(
                manager,
                [
                    "users",
                    "invite",
                    "foobar@example.com",
                    "Fred Foobar",
                    "redash-admin@example.com",
                ],
            )
            self.assertFalse(result.exception)
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(iu.called)
            c = iu.call_args[0]
            db.session.add_all(c)
            self.assertEqual(c[0].id, self.factory.org.id)
            self.assertEqual(c[1].id, admin.id)
            self.assertEqual(c[2].email, "foobar@example.com")

    def test_list(self):
        self.factory.create_user(name="Fred Foobar", email="foobar@example.com", org=self.factory.org)

        self.factory.create_user(name="William Foobar", email="william@example.com", org=self.factory.org)

        self.factory.create_user(name="Andrew Foobar", email="andrew@example.com", org=self.factory.org)

        runner = CliRunner()
        result = runner.invoke(manager, ["users", "list"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        output = """
        Id: 3
        Name: Andrew Foobar
        Email: andrew@example.com
        Organization: Default
        Active: True
        Groups: default
        --------------------
        Id: 1
        Name: Fred Foobar
        Email: foobar@example.com
        Organization: Default
        Active: True
        Groups: default
        --------------------
        Id: 2
        Name: William Foobar
        Email: william@example.com
        Organization: Default
        Active: True
        Groups: default
        """
        self.assertMultiLineEqual(result.output, textwrap.dedent(output).lstrip())

    def test_grant_admin(self):
        u = self.factory.create_user(
            name="Fred Foobar",
            email="foobar@example.com",
            org=self.factory.org,
            group_ids=[self.factory.default_group.id],
        )
        runner = CliRunner()
        result = runner.invoke(manager, ["users", "grant_admin", "foobar@example.com"])
        self.assertFalse(result.exception)
        self.assertEqual(result.exit_code, 0)
        db.session.add(u)
        self.assertEqual(u.group_ids, [u.org.default_group.id, u.org.admin_group.id])


class DatabaseCommandTests(BaseTestCase):
    def test_wait_for_db_connection_success(self):
        """Test that _wait_for_db_connection succeeds when connection is available."""
        # This should work since we have a test database
        _wait_for_db_connection(db)
        # If we get here without exception, the test passed

    def test_wait_for_db_connection_with_success(self):
        """Test that _wait_for_db_connection succeeds without sleeping on first try."""
        # Mock time.sleep to verify it's not called on success
        with mock.patch("time.sleep") as mock_sleep:
            _wait_for_db_connection(db)
            # Sleep should not be called on success
            mock_sleep.assert_not_called()

    def test_wait_for_db_connection_sleeps_on_failure(self):
        """Test that _wait_for_db_connection sleeps when connection fails."""
        call_count = [0]

        def mock_connect():
            call_count[0] += 1
            raise DatabaseError("Connection failed", None, None)

        # Mock time.sleep to avoid waiting 30 seconds in test
        with mock.patch("time.sleep") as mock_sleep:
            with mock.patch.object(db.engine, "connect", side_effect=mock_connect):
                _wait_for_db_connection(db)
                # Function attempts connection once, then gives up
                self.assertEqual(call_count[0], 1)
                # Should have slept once for 30 seconds
                mock_sleep.assert_called_once_with(30)

    def test_is_db_empty_with_tables(self):
        """Test that is_db_empty returns False when tables exist."""
        # The test database should have tables created
        result = is_db_empty()
        self.assertFalse(result)

    def test_is_db_empty_without_tables(self):
        """Test that is_db_empty returns True when no tables exist."""
        # Mock the inspector to return no tables
        with mock.patch("sqlalchemy.inspect") as mock_inspect:
            mock_inspector = mock.MagicMock()
            mock_inspector.get_table_names.return_value = []
            mock_inspect.return_value = mock_inspector

            result = is_db_empty()
            self.assertTrue(result)

    def test_load_extensions(self):
        """Test that load_extensions executes CREATE EXTENSION commands."""
        # Mock the settings to include test extensions
        test_extensions = ["pg_trgm", "hstore"]
        with mock.patch.object(settings.dynamic_settings, "database_extensions", test_extensions):
            # Mock the connection execute to track calls
            with mock.patch.object(db.engine, "connect") as mock_connect:
                mock_conn = mock.MagicMock()
                mock_connect.return_value.__enter__.return_value = mock_conn

                load_extensions(db)

                # Verify that execute was called for each extension
                self.assertEqual(mock_conn.execute.call_count, len(test_extensions))

    def test_create_tables_command_with_existing_tables(self):
        """Test the create_tables CLI command when tables already exist."""
        runner = CliRunner()

        # Mock is_db_empty to return False so we upgrade instead
        with mock.patch("redash.cli.database.is_db_empty", return_value=False):
            with mock.patch("redash.cli.database.upgrade") as mock_upgrade:
                result = runner.invoke(manager, ["database", "create_tables"])

                self.assertEqual(result.exit_code, 0)
                mock_upgrade.assert_called_once()
                self.assertIn("existing redash tables detected", result.output)

    def test_drop_tables_command(self):
        """Test the drop_tables CLI command."""
        runner = CliRunner()

        with mock.patch("redash.cli.database._wait_for_db_connection"):
            with mock.patch.object(db, "drop_all") as mock_drop_all:
                result = runner.invoke(manager, ["database", "drop_tables"])

                self.assertEqual(result.exit_code, 0)
                mock_drop_all.assert_called_once()

    def test_sqlalchemy_2x_connection_context(self):
        """Test that connection context manager works with SQLAlchemy 2.x."""
        # This tests the pattern used in _wait_for_db_connection
        with db.engine.connect() as conn:
            result = conn.execute(text("SELECT 1;"))
            row = result.fetchone()
            self.assertEqual(row[0], 1)
