from redash.models import Organization, db
from tests import BaseTestCase


class TestOrganizationLookup(BaseTestCase):
    def test_get_by_slug_returns_org(self):
        org = self.factory.org
        self.assertIs(Organization.get_by_slug(org.slug), org)

    def test_get_by_slug_returns_none_for_unknown_slug(self):
        self.assertIsNone(Organization.get_by_slug("no-such-slug"))

    def test_get_by_id_returns_org(self):
        org = self.factory.org
        self.assertIs(Organization.get_by_id(org.id), org)


class TestOrganizationGroups(BaseTestCase):
    def test_default_group_is_returned(self):
        org = self.factory.org
        self.assertIsNotNone(org.default_group)
        self.assertEqual(org.default_group.name, "default")

    def test_admin_group_is_returned(self):
        org = self.factory.org
        self.assertIsNotNone(org.admin_group)
        self.assertEqual(org.admin_group.name, "admin")

    def test_default_and_admin_groups_are_different(self):
        org = self.factory.org
        self.assertNotEqual(org.default_group.id, org.admin_group.id)


class TestOrganizationSettings(BaseTestCase):
    def test_google_apps_domains_defaults_to_empty_list(self):
        org = self.factory.org
        self.assertEqual(org.google_apps_domains, [])

    def test_google_apps_domains_returns_configured_value(self):
        org = self.factory.org
        org.settings[Organization.SETTING_GOOGLE_APPS_DOMAINS] = ["example.com"]
        self.assertEqual(org.google_apps_domains, ["example.com"])

    def test_is_public_defaults_to_false(self):
        org = self.factory.org
        self.assertFalse(org.is_public)

    def test_is_public_returns_true_when_set(self):
        org = self.factory.org
        org.settings[Organization.SETTING_IS_PUBLIC] = True
        self.assertTrue(org.is_public)

    def test_is_disabled_defaults_to_false(self):
        org = self.factory.org
        self.assertFalse(org.is_disabled)

    def test_disable_sets_is_disabled(self):
        org = self.factory.org
        org.disable()
        self.assertTrue(org.is_disabled)

    def test_enable_clears_is_disabled(self):
        org = self.factory.org
        org.disable()
        org.enable()
        self.assertFalse(org.is_disabled)

    def test_set_setting_persists_value(self):
        org = self.factory.org
        org.set_setting("date_format", "MM/DD/YY")
        db.session.commit()
        reloaded = Organization.get_by_id(org.id)
        self.assertEqual(reloaded.get_setting("date_format"), "MM/DD/YY")

    def test_set_setting_raises_for_unknown_key(self):
        org = self.factory.org
        with self.assertRaises(KeyError):
            org.set_setting("no_such_setting", "value")

    def test_get_setting_returns_default_when_not_overridden(self):
        org = self.factory.org
        value = org.get_setting("date_format")
        self.assertIsNotNone(value)

    def test_get_setting_raises_for_unknown_key(self):
        org = self.factory.org
        with self.assertRaises(KeyError):
            org.get_setting("no_such_setting")

    def test_get_setting_returns_none_for_unknown_key_when_raise_disabled(self):
        org = self.factory.org
        result = org.get_setting("no_such_setting", raise_on_missing=False)
        self.assertIsNone(result)


class TestOrganizationHasUser(BaseTestCase):
    def test_has_user_returns_true_for_existing_email(self):
        user = self.factory.create_user()
        self.assertTrue(self.factory.org.has_user(user.email))

    def test_has_user_returns_false_for_unknown_email(self):
        self.assertFalse(self.factory.org.has_user("nobody@example.com"))

    def test_has_user_returns_false_for_user_in_different_org(self):
        other_org = self.factory.create_org()
        other_user = self.factory.create_user(org=other_org)
        self.assertFalse(self.factory.org.has_user(other_user.email))


class TestOrganizationStr(BaseTestCase):
    def test_str_includes_name_and_id(self):
        org = self.factory.org
        result = str(org)
        self.assertIn(org.name, result)
        self.assertIn(str(org.id), result)
