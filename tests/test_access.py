import base64
import os
import tempfile
import time
import unittest
from pathlib import Path

from p24_foundation.access import AccessPolicy
from p24_foundation.errors import FoundationError
from p24_foundation.privacy import canonical
from p24_foundation.cli import read_private_access_token
from tests.helpers import TEST_ACCESS_PRIVATE_KEY,issue_test_access_token


class SignedAccessTests(unittest.TestCase):
    def setUp(self):
        self.namespace='access-fixture'
        self.policy=AccessPolicy(TEST_ACCESS_PRIVATE_KEY.public_key(),self.namespace)

    def test_investigator_role_is_narrow_and_token_is_bound_to_namespace(self):
        token=issue_test_access_token(self.namespace,('investigator',))
        principal=self.policy.authorize(token,'read_evidence')
        self.assertEqual((principal.subject,principal.roles),('operator-test',frozenset({'investigator'})))
        self.assertEqual(self.policy.authorize(token,'read_run').subject,'operator-test')
        self.assertEqual(self.policy.authorize(token,'read_publication').subject,'operator-test')
        with self.assertRaises(FoundationError) as error:self.policy.authorize(token,'place_hold')
        self.assertEqual(error.exception.code,'access_role_insufficient')
        other=AccessPolicy(TEST_ACCESS_PRIVATE_KEY.public_key(),'another-namespace')
        with self.assertRaises(FoundationError) as error:other.authorize(token,'read_request')
        self.assertEqual(error.exception.code,'access_namespace_mismatch')

    def test_missing_expired_too_long_and_invalid_signature_are_rejected(self):
        signed=issue_test_access_token(self.namespace)
        body,signature=signed.rsplit('.',1)
        tampered=body+'.'+(('B' if signature[0]=='A' else 'A')+signature[1:])
        cases=(
            ('expired',issue_test_access_token(self.namespace,now=int(time.time())-7200),'access_credential_expired'),
            ('long',self._custom_token(exp=int(time.time())+MAX_LIFETIME+1),'access_credential_invalid'),
            ('signature',tampered,'access_credential_invalid'),
        )
        for name,token,expected in cases:
            with self.subTest(name=name),self.assertRaises(FoundationError) as error:self.policy.authorize(token,'read_request')
            self.assertEqual(error.exception.code,expected)
        with self.assertRaises(FoundationError) as error:self.policy.authorize(None,'read_request')
        self.assertEqual(error.exception.code,'access_credential_invalid')

    def test_unknown_role_and_claim_extension_fail_closed(self):
        with self.assertRaises(FoundationError):self.policy.authorize(issue_test_access_token(self.namespace,('administrator',)),'read_request')
        token=self._custom_token(extra={'email':'private@example.test'})
        with self.assertRaises(FoundationError):self.policy.authorize(token,'read_request')

    @unittest.skipIf(os.name=='nt','POSIX mode-bit check is not a Windows ACL qualification')
    def test_access_token_file_rejects_group_or_world_readable_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'token';path.write_text(issue_test_access_token(self.namespace),encoding='utf-8')
            path.chmod(0o644)
            with self.assertRaises(FoundationError) as error:read_private_access_token(path)
            self.assertEqual(error.exception.code,'private_access_token_file_invalid')

    def _custom_token(self,*,exp=None,extra=None):
        import uuid
        now=int(time.time())
        claims=dict(version=1,iss='p24-foundation-local',aud='p24-evidence-inspection',namespace=self.namespace,
                    subject='operator-test',roles=['investigator'],iat=now,exp=exp or now+3600,jti=str(uuid.uuid4()))
        claims.update(extra or {})
        body=canonical(claims)
        enc=lambda value:base64.urlsafe_b64encode(value).decode().rstrip('=')
        return enc(body)+'.'+enc(TEST_ACCESS_PRIVATE_KEY.sign(body))


MAX_LIFETIME=8*60*60
