"""Read-only evidence for externally supervised project frontends.

Only known entry scripts actually present in a listener's ancestor chain are
read. Their source is private diagnostic data, never executed or published.
Process IDs and command lines alone do not authorize stopping a supervisor.
"""
import hashlib
import ntpath
from pathlib import Path
import re

SCRIPT_PATH=re.compile(r'''"([^"\r\n]+\.(?:ps1|py))"|'([^'\r\n]+\.(?:ps1|py))'|([A-Za-z]:\\[^\s"'\r\n]+\.(?:ps1|py))''',re.I)
ENTRY_NAMES={'service_entry.ps1','lan_proxy.py'}
MAX_FILE_BYTES=256*1024
MAX_TOTAL_BYTES=512*1024


def listener_ancestry(snapshot):
    processes={int(p['ProcessId']):p for p in snapshot['processes']};rows=[];seen=set()
    for listener in snapshot['listeners']:
        pid=int(listener['OwningProcess']);chain=[]
        while pid in processes and pid not in seen and len(chain)<12:
            value=processes[pid];seen.add(pid);chain.append(value)
            executable=ntpath.basename(value.get('ExecutablePath') or '').lower()
            # Do not treat Task Scheduler, SCM or other system service hosts
            # as project services. Record the boundary without controlling it.
            if executable in ('services.exe','svchost.exe','wininit.exe','smss.exe'):break
            pid=int(value.get('ParentProcessId',0))
        if chain:rows.append(dict(listener=dict(listener),ancestor_chain=chain))
    return rows


def supervisor_sources(ancestry,*,reader=None):
    """Bound both individual reads and total private source evidence."""
    paths={}
    for item in ancestry:
        for process in item['ancestor_chain']:
            for match in SCRIPT_PATH.finditer(process.get('CommandLine') or ''):
                path=next(part for part in match.groups() if part is not None)
                if ntpath.basename(path).lower() in ENTRY_NAMES:
                    record=paths.setdefault(path,dict(path=path,observed_processes=[]))
                    record['observed_processes'].append(process['ProcessId'])
    records=[];remaining=MAX_TOTAL_BYTES
    for path,record in sorted(paths.items()):
        try:
            if remaining<=0:
                record.update(status='SOURCE_BYTE_BUDGET_EXCEEDED',read_limit_bytes=0);records.append(record);continue
            limit=min(MAX_FILE_BYTES+1,remaining)
            if reader is None:
                with Path(path).open('rb') as stream:body=stream.read(limit)
            else:body=reader(path,limit)
            remaining=max(0,remaining-len(body))
            if len(body)==limit:
                record.update(status='SOURCE_BYTE_BUDGET_EXCEEDED',read_limit_bytes=limit)
            else:
                encoding='utf-16' if body.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
                record.update(status='READ_ONLY_SOURCE',bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),
                    encoding=encoding,content=body.decode(encoding,errors='replace'),executed=False)
        except OSError as exc:record.update(status='SOURCE_UNAVAILABLE',error_type=type(exc).__name__,errno=exc.errno)
        records.append(record)
    return records
