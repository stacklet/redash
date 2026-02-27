from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from redash import settings


class Redash(Flask):
    """A custom Flask app for Redash"""

    def __init__(self, *args, **kwargs):
        kwargs.update(
            {
                "template_folder": settings.FLASK_TEMPLATE_PATH,
                "static_folder": settings.STATIC_ASSETS_PATH,
                "static_url_path": "/static",
            }
        )
        super(Redash, self).__init__(__name__, *args, **kwargs)
        # Make sure we get the right referral address even behind proxies like nginx.
        self.wsgi_app = ProxyFix(self.wsgi_app, x_for=settings.PROXIES_COUNT, x_host=1)
        # Configure Redash using our settings
        self.config.from_object("redash.settings")


def create_app():
    from . import (
        authentication,
        handlers,
        limiter,
        mail,
        migrate,
        security,
        tasks,
    )
    from .handlers.webpack import configure_webpack
    from .metrics import request as request_metrics
    from .models import db, users
    from .utils import sentry
    from .version_check import reset_new_version_status

    sentry.init()
    app = Redash()

    # Check and update the cached version for use by the client
    reset_new_version_status()

    security.init_app(app)
    request_metrics.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    authentication.init_app(app)
    limiter.init_app(app)
    handlers.init_app(app)
    configure_webpack(app)
    users.init_app(app)
    tasks.init_app(app)

    # Ensure sessions are properly cleaned up after each request
    # This is critical for SQLAlchemy 2.0 to avoid idle transactions.
    # teardown_appcontext is intentionally omitted: Flask-SQLAlchemy 3.x
    # registers its own teardown_appcontext handler that calls session.remove().
    @app.teardown_request
    def shutdown_session_request(exception=None):
        # Provides earlier cleanup than teardown_appcontext and also covers
        # test client requests. remove() calls close() then clears the registry.
        db.session.remove()

    return app
