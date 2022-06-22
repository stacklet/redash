import logging
import jwt
import requests
import simplejson
from jwt.exceptions import (
    PyJWTError,
    InvalidTokenError,
    MissingRequiredClaimError,
    ExpiredSignatureError,
)

from redash.settings.organization import settings as org_settings

logger = logging.getLogger("jwt_auth")


def get_public_keys(url):
    """
    Returns:
        List of RSA public keys usable by PyJWT.
    """
    key_cache = get_public_keys.key_cache
    if url in key_cache:
        return key_cache[url]
    else:
        r = requests.get(url)
        r.raise_for_status()
        data = r.json()
        if "keys" in data:
            public_keys = []
            for key_dict in data["keys"]:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(
                    simplejson.dumps(key_dict)
                )
                public_keys.append(public_key)

            get_public_keys.key_cache[url] = public_keys
            return public_keys
        else:
            get_public_keys.key_cache[url] = data
            return data


get_public_keys.key_cache = {}


def verify_jwt_token(
    jwt_token, expected_issuer, expected_audience, expected_client_id, algorithms, public_certs_url
):
    # https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/
    # https://cloud.google.com/iap/docs/signed-headers-howto
    # Loop through the keys since we can't pass the key set to the decoder
    keys = get_public_keys(public_certs_url)

    key_id = jwt.get_unverified_header(jwt_token).get("kid", "")
    if key_id and isinstance(keys, dict):
        keys = [keys.get(key_id)]

    valid_token = False
    payload = None
    for i, key in enumerate(keys):
        try:
            # decode returns the claims which has the email if you need it
            payload = jwt.decode(
                jwt_token, key=key, audience=expected_audience, algorithms=algorithms
            )
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
            logging.info("Rejecting JWT token for key %d: %s", i, e)
        except Exception as e:
            logging.exception("Error processing JWT token: %s", e)
            break
    return payload, valid_token
