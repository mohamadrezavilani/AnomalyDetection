"""Check real routes on the preserved listeners and the identity of their serving process."""
import argparse
from http.client import HTTPConnection
import json
from urllib.parse import urlsplit
from compact_product.config import load
from compact_product.runtime import status


def probe(project, sha, review=None):
    cfg,_,_ = load(project)
    role = status(project)['web']
    if not role['running'] or role.get('package',{}).get('source_sha256')!=sha:
        raise ValueError('preserved_web_lease_does_not_match_installed_code')
    target_paths = ['/healthz','/','/sessions']
    if review:
        if urlsplit(review).path != '/incidents' or not review.startswith('/incidents?'):
            raise ValueError('invalid_historical_review_url')
        target_paths.append(review)
    checks=[]
    for port in cfg.web_ports:
        for path in target_paths:
            client=HTTPConnection('127.0.0.1',port,timeout=15)
            try:
                client.request('GET',path)
                response=client.getresponse()
                body=response.read(2*1024*1024)
                if response.status!=200:
                    raise ValueError('preserved_web_route_unavailable')
                if path=='/healthz' and json.loads(body).get('build')!=role['build']:
                    raise ValueError('unexpected_web_build_on_old_port')
                checks.append(dict(port=port,path=path,http_status=response.status))
            finally:
                client.close()
    return dict(build=role['build'],routes=checks)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project",required=True)
    p.add_argument("--sha",required=True)
    p.add_argument("--review")
    a=p.parse_args()
    # The lease appears slightly before Waitress binds its listeners on restart.
    import time
    deadline = time.monotonic() + 25
    while True:
        try:
            result = probe(a.project,a.sha,a.review)
            print(json.dumps(result))
            break
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.5)
