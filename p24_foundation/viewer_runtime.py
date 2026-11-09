"""Non-blocking console output and atomic safe reports for Viewer commands."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import os
import queue
import sys
import tempfile
import threading
import time


def atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,
                                         prefix=path.name+'.',suffix='.tmp',delete=False) as stream:
            temporary=Path(stream.name)
            json.dump(value,stream,ensure_ascii=True,indent=2);stream.write('\n')
            stream.flush();os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()


def runtime_source_digest(root=None):
    root=Path(root) if root is not None else Path(__file__).resolve().parents[1]
    digest=hashlib.sha256()
    for folder in ('p24_foundation','tools','review_ui','catalogs'):
        for path in sorted((root/folder).rglob('*')):
            if path.is_file() and path.suffix in ('.py','.html','.css','.js','.json','.csv') and '__pycache__' not in path.parts:
                digest.update(path.relative_to(root).as_posix().encode()+b'\0')
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


class ProgressConsole:
    """A stalled/selected terminal cannot hold a publication transaction open.

    Only this daemon thread performs console I/O. The worker updates a small
    state snapshot and a bounded queue without waiting for the terminal.
    Durable report files remain authoritative if console messages are dropped.
    """
    def __init__(self,stream=None,*,heartbeat_seconds=15,min_interval=0,capacity=128):
        self.stream=stream if stream is not None else sys.stdout
        try:self.fd=self.stream.fileno()
        except (AttributeError,OSError,ValueError):self.fd=None
        self.started=time.monotonic();self.heartbeat_seconds=heartbeat_seconds
        self.min_interval=min_interval;self.pending=queue.Queue(maxsize=capacity)
        self.stopped=threading.Event();self.state_lock=threading.Lock()
        self.latest={};self.last_stage=None;self.last_emit=0
        self.dropped=0;self.io_errors=0
        self.thread=threading.Thread(target=self._write_loop,daemon=True)
        self.thread.start()
    def emit(self,message):
        try:self.pending.put_nowait(message)
        except queue.Full:
            self.dropped+=1
            try:self.pending.get_nowait()
            except queue.Empty:pass
            try:self.pending.put_nowait(message)
            except queue.Full:pass
    def progress(self,event):
        now=time.monotonic()
        with self.state_lock:
            self.latest=dict(event)
            show=(event.get('stage')!=self.last_stage or now-self.last_emit>=self.min_interval)
            if show:self.last_stage=event.get('stage');self.last_emit=now
        if show:self.emit(dict(progress=event,elapsed_seconds=round(now-self.started,3)))
    def _write_loop(self):
        heartbeat_at=time.monotonic()+self.heartbeat_seconds
        while not self.stopped.is_set() or not self.pending.empty():
            try:message=self.pending.get(timeout=.1)
            except queue.Empty:
                if self.stopped.is_set():break
                if self.heartbeat_seconds<=0 or time.monotonic()<heartbeat_at:continue
                with self.state_lock:event=dict(self.latest)
                heartbeat_at=time.monotonic()+self.heartbeat_seconds
                if not event:continue
                message=dict(progress=event,elapsed_seconds=round(time.monotonic()-self.started,3),heartbeat=True)
            if self.io_errors:continue
            try:
                line=json.dumps(message,ensure_ascii=True)+'\n'
                if self.fd is None:self.stream.write(line);self.stream.flush()
                else:
                    # Avoid holding Python stdout's buffered lock while a
                    # Windows terminal is paused or a pipe is not consumed.
                    data=line.encode('ascii')
                    while data:data=data[os.write(self.fd,data):]
            except (OSError,ValueError):self.io_errors+=1
    def close(self,timeout=1):
        self.stopped.set();self.thread.join(timeout=timeout)
