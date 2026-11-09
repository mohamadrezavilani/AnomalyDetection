from pathlib import Path
import json
from decimal import Decimal
import base64
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from p24_foundation.access import AccessPolicy
from p24_foundation.privacy import canonical
from p24_foundation.privacy import Keys
from p24_foundation.intake import decode_batch,read_batch
from p24_foundation.parser import Semantics,normalize_event
from p24_foundation.store import stable_id

ROOT=Path(__file__).resolve().parents[1]
# Public synthetic test keys, never production configuration or original keys.
TEST_KEYS=Keys(b'\x11'*32,b'\x22'*32,'test_v1')
TEST_ACCESS_PRIVATE_KEY=Ed25519PrivateKey.from_private_bytes(b'\x33'*32)

def issue_test_access_token(namespace,roles=('investigator',),*,subject='operator-test',now=None):
    issued=int(time.time() if now is None else now)
    claims=dict(version=1,iss='p24-foundation-local',aud='p24-evidence-inspection',namespace=namespace,
                subject=subject,roles=list(roles),iat=issued,exp=issued+3600,jti=str(uuid.uuid4()))
    body=canonical(claims)
    enc=lambda value:base64.urlsafe_b64encode(value).decode().rstrip('=')
    return enc(body)+'.'+enc(TEST_ACCESS_PRIVATE_KEY.sign(body))

def test_access_policy(namespace):
    return AccessPolicy(TEST_ACCESS_PRIVATE_KEY.public_key(),namespace)
MANIFEST=json.loads((ROOT/'fixtures/MANIFEST.json').read_text(encoding='utf-8'))

def fixture(name):return read_batch(ROOT/'fixtures'/name)

def document(rid='request-A',oid='origin-A',at='2026-10-20T07:29:59Z',session='SESSION_A',ip='198.51.100.2',path='Core.v1/ConfigBasic Line:153',message=None):
    return {'_index':'fixture-index','_id':oid,'_source':{'@timestamp':at,'RequestID':rid,'Session':session,'IP':ip,'CallPath':path,'ExecutionTime':'1.2','ProcessID':'7','ThreadID':'2','Counter':'1','message':message or 'POST https://fixture.invalid/config HTTP/1.1 (G00000 | successful)','level':'Info'}}

def batch(rows):return decode_batch((json.dumps(rows,ensure_ascii=False,default=lambda x: float(x) if isinstance(x,Decimal) else str(x))+'\n').encode('utf-8'))

def normalized(rows,namespace='test-contract'):
    semantics=Semantics(ROOT/'catalogs/error_code_catalog.json');out=[]
    for ordinal,row in enumerate(rows):
        e=normalize_event(row,TEST_KEYS,namespace,semantics,fallback_scope='fixture-source',ordinal=ordinal)
        e['event_version_id']=stable_id(e['event_key'],e['content_digest'])
        out.append(e)
    return out

