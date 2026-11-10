"""OS-released lock for owned baseline writers; no PID-based process killing."""
from __future__ import annotations

from datetime import datetime,timezone
import errno
import json
import os
import re
from pathlib import Path
import time
import uuid

from . import BUILD_ID
from .snapshot import ContractError,require
from .files_io import atomic_json


def safe_failure(exc):
    code=str(exc) if isinstance(exc,ContractError) and re.fullmatch(r"[A-Z0-9_]+",str(exc)) else "WORKER_OPERATION_ERROR"
    sqlstate=getattr(exc,"sqlstate",None)
    return {"code":code,"error_type":type(exc).__name__,
            "sqlstate":sqlstate if isinstance(sqlstate,str) and re.fullmatch(r"[A-Z0-9]{5}",sqlstate) else None}


def read_json(path, default=None):
    path=Path(path)
    if not path.is_file(): return default
    if path.stat().st_size>8*1024*1024: raise ContractError("OWNED_STATUS_FILE_TOO_LARGE")
    value=json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value,dict): raise ContractError("OWNED_STATUS_OBJECT_REQUIRED")
    return value


def read_observed_json(path):
    """Best-effort telemetry only. Never use this for credentials or commands."""
    for attempt in range(3):
        try:
            return read_json(path, {}), None
        except (OSError, ValueError, ContractError) as exc:
            failure = safe_failure(exc)
            failure.update(errno=exc.errno if isinstance(getattr(exc, 'errno', None), int) else None,
                           winerror=exc.winerror if isinstance(getattr(exc, 'winerror', None), int) else None)
            if not isinstance(exc, PermissionError) or attempt == 2:
                return {}, failure
            time.sleep(.02 * (attempt + 1))


def write_json(path, value):
    for attempt in range(3):
        try:
            atomic_json(path,value)
            return
        except PermissionError:
            if attempt==2: raise
            time.sleep(.02*(attempt+1))


def lock_handle(handle):
    handle.seek(0)
    if os.name=="nt":
        import msvcrt
        msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)


def unlock_handle(handle):
    handle.seek(0)
    if os.name=="nt":
        import msvcrt
        msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(),fcntl.LOCK_UN)


def busy_error(exc):
    return exc.errno in (errno.EACCES,errno.EAGAIN,errno.EDEADLK)


class OwnedProcessLock:
    def __init__(self, root, job, source_sha256, *, resource="baseline", instance_token=None):
        self.root=Path(root).resolve()
        self.handle=None
        require(resource in ("baseline","actor","web"),"INVALID_OWNED_LOCK_RESOURCE")
        self.resource=resource
        require(instance_token is None or isinstance(instance_token,str) and re.fullmatch(r"[0-9a-f]{32}",instance_token),
                "INVALID_OWNED_INSTANCE_TOKEN")
        self.owner={"job":job,"pid":os.getpid(),"instance_token":instance_token or uuid.uuid4().hex,
                    "build_id":BUILD_ID,"source_sha256":source_sha256,
                    "started_at_utc":datetime.now(timezone.utc).isoformat()}

    def __enter__(self):
        path=self.root/("data/"+self.resource+"_process.lock")
        path.parent.mkdir(parents=True,exist_ok=True)
        handle=path.open("a+b")
        try:
            if path.stat().st_size==0:
                handle.write(b"0")
                handle.flush()
            try: lock_handle(handle)
            except OSError as exc:
                if busy_error(exc):
                    raise ContractError(self.resource.upper()+"_PROCESS_ALREADY_RUNNING") from None
                raise
            self.handle=handle
            write_json(self.root/("data/"+self.resource+"_process.json"),self.owner)
            return self
        except BaseException:
            if self.handle:
                unlock_handle(handle)
                self.handle=None
            handle.close()
            raise

    def __exit__(self,*_):
        try: unlock_handle(self.handle)
        finally:
            self.handle.close()
            self.handle=None
        # Do not unlink a lock file: a different inode could admit two writers.


def process_owner(root,resource='baseline'):
    root=Path(root).resolve()
    require(resource in ('baseline','actor','web'),'INVALID_OWNED_LOCK_RESOURCE')
    path=root/('data/'+resource+'_process.lock')
    if not path.exists(): return {"locked":False,"owner":None}
    with path.open("r+b") as handle:
        try: lock_handle(handle)
        except OSError as exc:
            if not busy_error(exc): raise
            locked=True
        else:
            unlock_handle(handle)
            locked=False
        owner,failure=read_observed_json(root/('data/'+resource+'_process.json'))
        result={"locked":locked,"owner":owner or None,
                "owner_read_status":"UNAVAILABLE" if failure else "AVAILABLE" if owner else "MISSING"}
        if failure: result['owner_read_failure']=failure
        return result
