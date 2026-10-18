import base64
import datetime
import os
import tempfile
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from saml2 import BINDING_HTTP_REDIRECT, samlp
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT
from saml2.config import IdPConfig
from saml2.metadata import entity_descriptor
from saml2.s_utils import decode_base64_and_inflate
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_TRANSIENT, NameID
from saml2.server import Server
from saml2.sigver import SignatureError

from redash import models, settings
from redash.authentication.saml_auth import get_saml_client
from tests import BaseTestCase

ENTITY_ID = "https://idp.example.com/saml"
SSO_URL = "https://idp.example.com/sso"


def make_keypair(directory, name):
    """Write a private key and self-signed certificate, returning their paths."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_path = os.path.join(directory, name + ".key")
    cert_path = os.path.join(directory, name + ".crt")
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path, base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


class TestSAMLAuthentication(BaseTestCase):
    def setUp(self):
        super().setUp()
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        self.tmpdir = tmpdir.name
        self.key_path, self.cert_path, cert_der = make_keypair(self.tmpdir, "idp")
        self.other_key_path, self.other_cert_path, _ = make_keypair(self.tmpdir, "other")

        org = self.factory.org
        org.set_setting("auth_saml_enabled", True)
        org.set_setting("auth_saml_type", "static")
        org.set_setting("auth_saml_entity_id", ENTITY_ID)
        org.set_setting("auth_saml_sso_url", SSO_URL)
        org.set_setting("auth_saml_x509_cert", cert_der)
        models.db.session.commit()

        self.acs_url = "http://localhost/{}/saml/callback".format(org.slug)

    def disable_saml(self):
        # Each request removes the session, which detaches self.factory.org,
        # so load the organization again before changing it.
        org = models.db.session.get(models.Organization, self.factory.org.id)
        org.set_setting("auth_saml_enabled", False)
        models.db.session.commit()

    def sp_metadata(self):
        with self.app.test_request_context("/"):
            client = get_saml_client(self.factory.org)
        return str(entity_descriptor(client.config))

    def signed_response(self, email, attributes, key_path=None, cert_path=None, sign=True, encrypt=False):
        """Build a base64 SAML response with an assertion signed by the test IdP.

        With encrypt, the IdP encrypts the assertion to the encryption
        certificate in the SP metadata.
        """
        config = IdPConfig()
        config.load(
            {
                "entityid": ENTITY_ID,
                "service": {
                    "idp": {
                        "endpoints": {"single_sign_on_service": [(SSO_URL, BINDING_HTTP_REDIRECT)]},
                        "policy": {"default": {"attribute_restrictions": None}},
                    }
                },
                "key_file": key_path or self.key_path,
                "cert_file": cert_path or self.cert_path,
                "metadata": {"inline": [self.sp_metadata()]},
            }
        )
        response = Server(config=config).create_authn_response(
            identity=attributes,
            in_response_to=None,
            destination=self.acs_url,
            sp_entity_id=ENTITY_ID,
            name_id=NameID(format=NAMEID_FORMAT_EMAILADDRESS, text=email),
            authn={"class_ref": PASSWORDPROTECTEDTRANSPORT},
            sign_assertion=sign,
            encrypt_assertion=encrypt,
        )
        return base64.b64encode(str(response).encode()).decode()

    def test_sp_initiated_redirects_to_idp_with_authn_request(self):
        rv = self.get_request("/saml/login", org=self.factory.org)

        self.assertEqual(rv.status_code, 302)
        self.assertEqual(rv.headers["Cache-Control"], "no-cache, no-store")
        self.assertEqual(rv.headers["Pragma"], "no-cache")
        location = urlparse(rv.headers["Location"])
        self.assertEqual("{}://{}{}".format(location.scheme, location.netloc, location.path), SSO_URL)

        saml_request = parse_qs(location.query)["SAMLRequest"][0]
        authn_request = samlp.authn_request_from_string(decode_base64_and_inflate(saml_request))
        self.assertEqual(authn_request.destination, SSO_URL)
        self.assertEqual(authn_request.issuer.text, ENTITY_ID)
        self.assertEqual(authn_request.name_id_policy.format, NAMEID_FORMAT_TRANSIENT)

    def test_sp_initiated_disabled(self):
        self.disable_saml()

        rv = self.get_request("/saml/login", org=self.factory.org)

        self.assertEqual(rv.status_code, 302)
        self.assertNotIn(SSO_URL, rv.headers["Location"])

    def test_callback_creates_and_logs_in_user(self):
        saml_response = self.signed_response(
            "ada@example.com",
            {"FirstName": ["Ada"], "LastName": ["Lovelace"], "RedashGroups": ["admin"]},
        )

        rv = self.post_request("/saml/callback", data={"SAMLResponse": saml_response}, org=self.factory.org)

        self.assertEqual(rv.status_code, 302)
        self.assertTrue(rv.headers["Location"].endswith("/{}/".format(self.factory.org.slug)))
        user = models.User.get_by_email_and_org("ada@example.com", self.factory.org)
        self.assertEqual(user.name, "Ada Lovelace")
        self.assertIn(self.factory.org.admin_group.id, user.group_ids)

        rv = self.get_request("/api/session", org=self.factory.org)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.json["user"]["email"], "ada@example.com")

    def test_callback_rejects_assertion_signed_by_other_key(self):
        saml_response = self.signed_response(
            "mallory@example.com",
            {"FirstName": ["Mallory"], "LastName": ["Example"]},
            key_path=self.other_key_path,
            cert_path=self.other_cert_path,
        )

        with self.assertLogs("saml_auth", "ERROR") as logs:
            rv = self.post_request("/saml/callback", data={"SAMLResponse": saml_response}, org=self.factory.org)
        self.assertIsInstance(logs.records[0].exc_info[1], SignatureError)

        self.assertEqual(rv.status_code, 302)
        self.assertIn("/{}/login".format(self.factory.org.slug), rv.headers["Location"])
        self.assertEqual(
            models.User.query.filter(models.User.email == "mallory@example.com").count(),
            0,
        )

    def test_callback_rejects_unsigned_assertion(self):
        saml_response = self.signed_response(
            "mallory@example.com",
            {"FirstName": ["Mallory"], "LastName": ["Example"]},
            sign=False,
        )

        with self.assertLogs("saml_auth", "ERROR") as logs:
            rv = self.post_request("/saml/callback", data={"SAMLResponse": saml_response}, org=self.factory.org)
        self.assertIsInstance(logs.records[0].exc_info[1], SignatureError)

        self.assertEqual(rv.status_code, 302)
        self.assertIn("/{}/login".format(self.factory.org.slug), rv.headers["Location"])
        self.assertEqual(
            models.User.query.filter(models.User.email == "mallory@example.com").count(),
            0,
        )

    def test_callback_decrypts_encrypted_assertion(self):
        sp_key_path, sp_cert_path, _ = make_keypair(self.tmpdir, "sp")
        with patch.multiple(
            settings,
            SAML_ENCRYPTION_ENABLED=True,
            SAML_ENCRYPTION_PEM_PATH=sp_key_path,
            SAML_ENCRYPTION_CERT_PATH=sp_cert_path,
        ):
            saml_response = self.signed_response(
                "ada@example.com",
                {"FirstName": ["Ada"], "LastName": ["Lovelace"]},
                encrypt=True,
            )
            decoded = base64.b64decode(saml_response).decode()
            self.assertIn("EncryptedAssertion", decoded)
            self.assertNotIn("ada@example.com", decoded)

            rv = self.post_request("/saml/callback", data={"SAMLResponse": saml_response}, org=self.factory.org)

        self.assertEqual(rv.status_code, 302)
        self.assertTrue(rv.headers["Location"].endswith("/{}/".format(self.factory.org.slug)))
        user = models.User.get_by_email_and_org("ada@example.com", self.factory.org)
        self.assertEqual(user.name, "Ada Lovelace")

    def test_callback_disabled(self):
        saml_response = self.signed_response("ada@example.com", {"FirstName": ["Ada"], "LastName": ["Lovelace"]})
        self.disable_saml()

        rv = self.post_request("/saml/callback", data={"SAMLResponse": saml_response}, org=self.factory.org)

        self.assertEqual(rv.status_code, 302)
        self.assertEqual(models.User.query.filter(models.User.email == "ada@example.com").count(), 0)
