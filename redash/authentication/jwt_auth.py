import logging
import jwt
import requests
import simplejson
from jwt.exceptions import (
    PyJWTError,
    ImmatureSignatureError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
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


def find_identity_in_payload(payload):
    if "email" in payload:
        return payload["email"]
    if "identities" in payload:
        for identity in payload["identities"]:
            if "email" in identity:
                return identity["email"]
            elif "userId" in identity:
                return identity["userId"]
            elif "nameId" in identity:
                return identity["nameId"]
    elif "username" in payload:
        return payload["username"]
    elif "cognito:username" in payload:
        return payload["cognito:username"]
    return None


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
        logger.info("Rejecting invalid JWT token: %s", e)
        raise

    if key_id and isinstance(keys, dict):
        keys = [keys.get(key_id)]

    payload = None
    identity = None
    valid_token = False
    any_key_valid = False
    for i, key in enumerate(keys):
        try:
            # decode returns the claims which has the email if you need it
            payload = jwt.decode(
                jwt_token, key=key, audience=expected_audience, algorithms=algorithms
            )
            any_key_valid = True
            issuer = payload["iss"]
            if issuer != expected_issuer:
                raise InvalidTokenError('Token has incorrect "issuer"')
            client_id = payload.get("client_id")
            if expected_client_id and expected_client_id != client_id:
                raise InvalidTokenError('Token has incorrect "client_id"')
            identity = find_identity_in_payload(payload)
            if not identity:
                raise InvalidTokenError(
                    "Unable to determine identity (missing email, username, or other identifier)"
                )
            # Ensure identity is in a consistent place, regardless of where we found it.
            payload["identity"] = identity
            valid_token = True
            break
        except (InvalidKeyError, InvalidSignatureError) as e:
            logger.info("Rejecting JWT token for key %d: %s", i, e)
            # Key servers can host multiple keys, only one of which would
            # actually be used for a given token. So if the check failed
            # due only to an issue with this key, we should just move on
            # to the next one.
            continue
        except (ImmatureSignatureError, ExpiredSignatureError) as e:
            logger.info("Rejecting JWT token: %s", e)
            # The key checked out, but the token was outside of the time-window
            # that it should be valid for. This is not an error but means they'll
            # need to log in again.
            any_key_valid = True
            continue
        except InvalidTokenError as e:
            logger.error("Rejecting invalid JWT token: %s", e)
            # Any other issue with the token means it has a fundamental issue so
            # if we send them to the login page it could cause a redirect loop.
            raise
        except Exception as e:
            logger.exception("Error processing JWT token: %s", e)
            raise InvalidTokenError("Error processing token") from e
    if not any_key_valid:
        logger.error("No valid keys for token")
        # If none of the keys from the key server are valid, it's a auth server
        # misconfiguration and sending them to the login page would definitely
        # cause a redirect loop.
        raise InvalidTokenError("No valid keys for token")
    return payload, identity, valid_token
