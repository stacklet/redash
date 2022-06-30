import json
import logging

import jwt
import requests
from jwt.exceptions import (
    PyJWTError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from redash.settings.organization import settings as org_settings

logger = logging.getLogger("jwt_auth")

FILE_SCHEME_PREFIX = "file://"


def get_public_key_from_file(url):
    file_path = url[len(FILE_SCHEME_PREFIX) :]
    with open(file_path) as key_file:
        key_str = key_file.read()

    get_public_keys.key_cache[url] = [key_str]
    return key_str


def get_public_key_from_net(url):
    r = requests.get(url)
    r.raise_for_status()
    data = r.json()
    if "keys" in data:
        public_keys = []
        for key_dict in data["keys"]:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
            public_keys.append(public_key)

        get_public_keys.key_cache[url] = public_keys
        return public_keys
    else:
        get_public_keys.key_cache[url] = data
        return data


def get_public_keys(url):
    """
    Returns:
        List of RSA public keys usable by PyJWT.
    """
    key_cache = get_public_keys.key_cache
    keys = {}
    if url in key_cache:
        keys = key_cache[url]
    else:
        if url.startswith(FILE_SCHEME_PREFIX):
            keys = [get_public_key_from_file(url)]
        else:
            keys = get_public_key_from_net(url)
    return keys


get_public_keys.key_cache = {}


def verify_jwt_token(
    jwt_token, expected_issuer, expected_audience, expected_client_id, algorithms, public_certs_url
):
    # https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/
    # https://cloud.google.com/iap/docs/signed-headers-howto
    # Loop through the keys since we can't pass the key set to the decoder
    keys = get_public_keys(public_certs_url)

    try:
        key_id = jwt.get_unverified_header(jwt_token).get("kid", "")
    except PyJWTError as e:
        logger.info("Ignoring invalid JWT token: %s", e)
        return None, False

    if key_id and isinstance(keys, dict):
        keys = [keys.get(key_id)]

    valid_token = False
    payload = None
    for i, key in enumerate(keys):
        try:
            # decode returns the claims which has the email if you need it
            payload = jwt.decode(jwt_token, key=key, audience=expected_audience, algorithms=algorithms)
            issuer = payload["iss"]
            if issuer != expected_issuer:
                raise InvalidTokenError("Wrong issuer: {}".format(issuer))
            client_id = payload.get("client_id")
            if expected_client_id and expected_client_id != client_id:
                raise InvalidTokenError("Wrong client_id: {}".format(client_id))
            user_claim = org_settings["auth_jwt_auth_user_claim"]
            if not payload.get(user_claim):
                raise MissingRequiredClaimError(user_claim)
            valid_token = True
            break
        except PyJWTError as e:
            logger.info("Rejecting JWT token for key %d: %s", i, e)
        except Exception as e:
            logger.exception("Error processing JWT token: %s", e)
            break
    return payload, valid_token
