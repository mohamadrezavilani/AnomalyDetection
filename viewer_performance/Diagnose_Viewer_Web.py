"""Read-only direct TCP/HTTP diagnosis, independent of all proxy settings."""
from __future__ import annotations
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time


def probe(host, port, path, *, timeout=5):
    began = time.monotonic()
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request('GET', path, headers={'Connection': 'close'})
        response = connection.getresponse()
        result = {'http_status': response.status, 'server': response.getheader('Server'),
                  'direct_socket': True}
        if path == '/healthz':
            body = response.read(4096)
            try:
                health = json.loads(body)
                if isinstance(health, dict):
                    result['health'] = {k: health[k] for k in ('status', 'service', 'runtime_sha256') if k in health}
            except (ValueError, UnicodeError):
                pass
        return result
    except Exception as exc:
        return {'error_type': type(exc).__name__, 'direct_socket': True}
    finally:
        connection.close()


def listeners(port):
    if os.name != 'nt':
        return {'status': 'WINDOWS_ONLY'}
    # Only identity metadata; never export arbitrary process command lines.
    script = ("$rows=@(Get-NetTCPConnection -State Listen -LocalPort " + str(port) +
        " -ErrorAction SilentlyContinue | ForEach-Object { $p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;name=$p.ProcessName;image=$p.Path} }); "
        "ConvertTo-Json -InputObject $rows -Compress")
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', script],
            capture_output=True, text=True, timeout=12, check=True)
        return {'status': 'READ', 'value': json.loads(result.stdout)}
    except Exception as exc:
        return {'status': 'UNAVAILABLE', 'error_type': type(exc).__name__}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5021)
    args = parser.parse_args(argv)
    address = ipaddress.ip_address(args.host)
    networks = [ipaddress.ip_network(n) for n in ('127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if not any(address in network for network in networks) or not 1 <= args.port <= 65535:
        raise ValueError('local_viewer_address_required')
    expected = json.loads((Path(__file__).resolve().parents[1]/'RELEASE_MANIFEST.json').read_text(encoding='utf-8-sig'))['runtime_source_sha256']
    health = probe(str(address), args.port, '/healthz')
    identity = health.get('health', {})
    verified = (health.get('http_status') == 200 and identity.get('status') == 'ok'
                and identity.get('service') == 'viewer' and identity.get('runtime_sha256') == expected)
    report = {'status': 'VIEWER_ORIGIN_VERIFIED' if verified else 'VIEWER_ORIGIN_NOT_VERIFIED',
              'host': str(address), 'port': args.port, 'health': health,
              'listener': listeners(args.port), 'database_modified': False, 'workers_restarted': False}
    if verified:
        report['home'] = probe(str(address), args.port, '/', timeout=15)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if verified and report['home'].get('http_status') == 200 else 2


if __name__ == '__main__':
    raise SystemExit(main())
