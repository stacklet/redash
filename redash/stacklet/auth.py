import functools
from urllib.parse import urlparse

import boto3

import logging

logger = logging.getLogger(__name__)


def get_iam_token(username, hostname, port):
    return boto3.client("rds").generate_db_auth_token(
        DBHostname=hostname, Port=port, DBUsername=username
    )
    # TODO: ensure the Source that we setup with dashboard.py sets these values correctly when using IAM auth
    # dsn["sslmode"] = "verify-full"
    # dsn["sslrootcert"] = os.environ.get(
    #     "ASSETDB_AWS_RDS_CA_BUNDLE",
    #     str(Path(__file__).parent / "stacklet" / "rds-combined-ca-bundle.pem"),
    # )
    # return dsn


def parse_iam_auth(host):
    """parse_iam_auth: parses the host and returns (True, host)
    if the iam_auth=true query parameter is found."""
    parsed_url = urlparse(host)
    return "iam_auth=true" in parsed_url.query, parsed_url.path


def inject_iam_auth(func):
    """inject_iam_auth: will look for the query string ?iam_auth=True in the connection URL.
    If found, the configuration password will be replaced with one generated via
    AWS RDS generate token call."""

    @functools.wraps(func)
    def wrapped_connection(*args, **kwargs):
        self = args[0]
        host = self.configuration.get("host")
        should_use_iam, iam_host = parse_iam_auth(host)

        if should_use_iam:
            self.configuration["host"] = iam_host
            self.configuration["password"] = get_iam_token(
                self.configuration.get("user"), iam_host, self.configuration.get("port")
            )

        return func(*args, **kwargs)

    return wrapped_connection
