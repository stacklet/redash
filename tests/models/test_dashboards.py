from redash.models import Dashboard, Favorite, db
from tests import BaseTestCase


class DashboardTest(BaseTestCase):
    def create_tagged_dashboard(self, tags):
        dashboard = self.factory.create_dashboard(tags=tags)
        ds = self.factory.create_data_source(group=self.factory.default_group)
        query = self.factory.create_query(data_source=ds)
        # We need a bunch of visualizations and widgets configured
        # to trigger wrong counts via the left outer joins.
        vis1 = self.factory.create_visualization(query_rel=query)
        vis2 = self.factory.create_visualization(query_rel=query)
        vis3 = self.factory.create_visualization(query_rel=query)
        widget1 = self.factory.create_widget(visualization=vis1, dashboard=dashboard)
        widget2 = self.factory.create_widget(visualization=vis2, dashboard=dashboard)
        widget3 = self.factory.create_widget(visualization=vis3, dashboard=dashboard)
        dashboard.layout = [[widget1.id, widget2.id, widget3.id]]
        db.session.commit()
        return dashboard

    def test_all_tags(self):
        self.create_tagged_dashboard(tags=["tag1"])
        self.create_tagged_dashboard(tags=["tag1", "tag2"])
        self.create_tagged_dashboard(tags=["tag1", "tag2", "tag3"])

        self.assertEqual(
            list(Dashboard.all_tags(self.factory.org, self.factory.user)),
            [("tag1", 3), ("tag2", 2), ("tag3", 1)],
        )


class TestDashboardsByUser(BaseTestCase):
    def test_returns_only_users_dashboards(self):
        d = self.factory.create_dashboard(user=self.factory.user)
        d2 = self.factory.create_dashboard(user=self.factory.create_user())

        dashboards = Dashboard.by_user(self.factory.user)

        # not using self.assertIn/NotIn because otherwise this fails :O
        self.assertTrue(d in list(dashboards))
        self.assertFalse(d2 in list(dashboards))

    def test_returns_drafts_by_the_user(self):
        d = self.factory.create_dashboard(is_draft=True)
        d2 = self.factory.create_dashboard(is_draft=True, user=self.factory.create_user())

        dashboards = Dashboard.by_user(self.factory.user)

        # not using self.assertIn/NotIn because otherwise this fails :O
        self.assertTrue(d in dashboards)
        self.assertFalse(d2 in dashboards)

    def test_returns_correct_number_of_dashboards(self):
        # Solving https://github.com/getredash/redash/issues/5466

        usr = self.factory.create_user()

        ds1 = self.factory.create_data_source()
        ds2 = self.factory.create_data_source()

        qry1 = self.factory.create_query(data_source=ds1, user=usr)
        qry2 = self.factory.create_query(data_source=ds2, user=usr)

        viz1 = self.factory.create_visualization(
            query_rel=qry1,
        )
        viz2 = self.factory.create_visualization(
            query_rel=qry2,
        )

        def create_dashboard():
            dash = self.factory.create_dashboard(name="boy howdy", user=usr)
            self.factory.create_widget(dashboard=dash, visualization=viz1)
            self.factory.create_widget(dashboard=dash, visualization=viz2)

            return dash

        create_dashboard()
        create_dashboard()

        results = Dashboard.all(self.factory.org, usr.group_ids, usr.id)

        self.assertEqual(2, results.count(), "The incorrect number of dashboards were returned")


class TestDashboardFavorites(BaseTestCase):
    def test_returns_only_favorited_dashboards(self):
        """Test Dashboard.favorites() returns only dashboards favorited by the user."""
        # Create two dashboards
        dashboard1 = self.factory.create_dashboard(name="Dashboard 1")
        dashboard2 = self.factory.create_dashboard(name="Dashboard 2")

        # Favorite only dashboard1
        favorite = Favorite(
            org_id=self.factory.org.id,
            object_type="Dashboard",
            object_id=dashboard1.id,
            user_id=self.factory.user.id,
        )
        db.session.add(favorite)
        db.session.commit()

        # Get favorited dashboards
        favorited = Dashboard.favorites(self.factory.user).all()

        # Should only return dashboard1
        self.assertEqual(len(favorited), 1)
        self.assertEqual(favorited[0].id, dashboard1.id)

    def test_favorites_excludes_non_favorited(self):
        """Test that non-favorited dashboards are not returned."""
        # Create three dashboards
        dashboard1 = self.factory.create_dashboard(name="Dashboard 1")
        dashboard2 = self.factory.create_dashboard(name="Dashboard 2")
        dashboard3 = self.factory.create_dashboard(name="Dashboard 3")

        # Favorite dashboard1 and dashboard3, but not dashboard2
        fav1 = Favorite(
            org_id=self.factory.org.id,
            object_type="Dashboard",
            object_id=dashboard1.id,
            user_id=self.factory.user.id,
        )
        fav3 = Favorite(
            org_id=self.factory.org.id,
            object_type="Dashboard",
            object_id=dashboard3.id,
            user_id=self.factory.user.id,
        )
        db.session.add_all([fav1, fav3])
        db.session.commit()

        # Get favorited dashboards
        favorited = Dashboard.favorites(self.factory.user).all()
        favorited_ids = {d.id for d in favorited}

        # Should return dashboard1 and dashboard3, but not dashboard2
        self.assertEqual(len(favorited), 2)
        self.assertIn(dashboard1.id, favorited_ids)
        self.assertIn(dashboard3.id, favorited_ids)
        self.assertNotIn(dashboard2.id, favorited_ids)
