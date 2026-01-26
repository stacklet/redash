import functools
from flask_login import login_required
from redash.handlers import routes
from redash.handlers.base import json_response
from redash.security import talisman
from redash.stacklet.config import get_application_config

@routes.route("/stacklet/config", methods=["GET"])
@talisman(force_https=False)
@login_required
@functools.cache
def stacklet_config():
    """Endpoint to expose application configuration from AWS SSM Parameter Store."""
    config = get_application_config()
    return json_response(config)
