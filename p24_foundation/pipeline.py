"""Durable, explicitly started five-minute design-pipeline supervision.

No automatic retry of a started window. Existing evidence limits stay enforced.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from .errors import FoundationError
from .privacy import canonical
from .replay import _write_report


def utc(value):
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None or dt.utcoffset() != timedelta(0) or dt.second or dt.microsecond or dt.minute % 5:
            raise ValueError()
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise FoundationError('pipeline_start_requires_aligned_utc') from None


def validate_spec(spec):
    required = {'version','start','windows','lag_seconds','window_timeout_seconds','config',
                'target_root','stream','index_pattern','rank_cutoff','persist_candidates'}
    if not isinstance(spec, dict) or set(spec) != required or spec['version'] != 'p24-pipeline.1':
        raise FoundationError('invalid_pipeline_spec')
    utc(spec['start'])
    for key, lo, hi in [('windows',1,128),('lag_seconds',0,3600),('window_timeout_seconds',1,3600)]:
        if isinstance(spec[key], bool) or not isinstance(spec[key], int) or not lo <= spec[key] <= hi:
            raise FoundationError('invalid_pipeline_bounds')
    if not isinstance(spec['persist_candidates'], bool):
        raise FoundationError('invalid_pipeline_spec')
    if not all(isinstance(spec[k],str) and spec[k] for k in ['config','target_root','stream','index_pattern']):
        raise FoundationError('invalid_pipeline_spec')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',spec['stream']):
        raise FoundationError('invalid_pipeline_stream')
    from fractions import Fraction
    try:
        if (not isinstance(spec['rank_cutoff'],str) or not re.fullmatch(r'(?:[0-9]{1,6}/[0-9]{1,6}|[01](?:\.[0-9]{1,6})?)',spec['rank_cutoff'])
                or not 0 < Fraction(spec['rank_cutoff']) < 1):
            raise ValueError()
    except (ValueError, ZeroDivisionError):
        raise FoundationError('invalid_behavior_rank_cutoff') from None
    return spec


@contextmanager
def ownership(directory):
    """OS lease survives stale files and releases on process exit; never delete it."""
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (directory/'owner.lock').open('a+b') as stream:
        stream.seek(0,os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b'0');stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            raise FoundationError('pipeline_already_running') from None
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(stream,fcntl.LOCK_UN)


def read_state(path):
    try:
        with path.open('rb') as stream:
            raw=stream.read(262145)
        if len(raw)>262144:raise ValueError()
        return json.loads(raw)
    except (OSError,ValueError):
        raise FoundationError('pipeline_state_unreadable') from None


def execute(command,timeout):
    """Bound one child, suppress unsafe stderr and reap on timeout/interruption."""
    process=None
    try:
        with tempfile.TemporaryFile() as output:
            process=subprocess.Popen(command,stdout=output,stderr=subprocess.DEVNULL,shell=False)
            process.wait(timeout=timeout)
            output.seek(0);raw=output.read(65537)
            if process.returncode or len(raw)>65536:
                raise FoundationError('pipeline_window_unconfirmed')
            value=json.loads(raw)
            if not isinstance(value,dict) or value.get('status')!='completed':
                raise ValueError()
            if isinstance(value.get('generation'),bool) or not isinstance(value.get('generation'),int) or value['generation']<1:
                raise ValueError()
            # Never reflect arbitrary worker text or paths into supervisor output.
            return {'status':'completed','publication_id':str(uuid.UUID(value['publication_id'])),
                    'generation':value['generation']}
    except (ValueError,KeyError,TypeError,subprocess.TimeoutExpired):
        raise FoundationError('pipeline_window_unconfirmed') from None
    finally:
        if process is not None and process.poll() is None:
            process.kill();process.wait()


def run(spec,directory,command,*,launch=execute,now=time.time,pause=time.sleep):
    """Resume only confirmed windows. An in-flight window requires reconciliation."""
    validate_spec(spec);directory=Path(directory).resolve();state_path=directory/'state.json'
    fingerprint=hashlib.sha256(canonical(spec)).hexdigest()
    with ownership(directory):
        if state_path.exists():
            state=read_state(state_path)
            if state.get('spec_sha256')!=fingerprint:
                raise FoundationError('pipeline_spec_changed')
            done=state.get('completed_windows')
            if isinstance(done,bool) or not isinstance(done,int) or not 0<=done<=spec['windows']:
                raise FoundationError('pipeline_state_invalid')
            if state.get('in_flight') is not None:
                raise FoundationError('pipeline_requires_reconciliation')
        else:
            _write_report(directory/'spec.json',spec,create=True)
            state=dict(version='p24-pipeline-state.1',spec_sha256=fingerprint,status='waiting',
                       completed_windows=0,in_flight=None,production_modified=False)
            _write_report(state_path,state,create=True)
        start=utc(spec['start'])
        try:
            while state['completed_windows']<spec['windows']:
                ordinal=state['completed_windows']
                end=start+timedelta(minutes=5*(ordinal+1))
                wait=end.timestamp()+spec['lag_seconds']-now()
                if wait>0:
                    pause(min(wait,1));continue
                window_dir=directory/f'window_{ordinal:04d}'
                # In-flight record precedes child launch: never guess a rollback.
                state.update(status='running',in_flight=ordinal)
                _write_report(state_path,state)
                try:
                    result=launch(list(command)+['--state-dir',str(directory),'--ordinal',str(ordinal)],spec['window_timeout_seconds'])
                    if result.get('status')!='completed':raise FoundationError('pipeline_window_unconfirmed')
                    recorded=read_state(window_dir/'result.json')
                    if recorded.get('publication_id')!=result.get('publication_id') or recorded.get('generation')!=result.get('generation'):
                        raise FoundationError('pipeline_window_unconfirmed')
                except BaseException:
                    state['status']='requires_reconciliation';_write_report(state_path,state)
                    raise
                state.update(completed_windows=ordinal+1,in_flight=None,status='waiting')
                _write_report(state_path,state)
            state['status']='completed';_write_report(state_path,state)
            return {k:state[k] for k in ['status','completed_windows','production_modified']}
        except KeyboardInterrupt:
            if state['in_flight'] is None:
                state['status']='stopped';_write_report(state_path,state)
            return dict(status=state['status'],completed_windows=state['completed_windows'],production_modified=False)
