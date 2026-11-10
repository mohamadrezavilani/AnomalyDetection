"""Bounded SQL timing for the owned connection; no statement or parameters.

Fingerprints identify fixed source statements, not user data. Cursor bulk
writes remain delegated; the trace does not claim coverage of their timing.
"""
from collections import deque
import hashlib
import time


class ObservedConnection:
    def __init__(self,raw,clock=None,*,observer=None):
        self.raw=raw;self.clock=clock or time.monotonic;self.recent=deque(maxlen=16)
        self.observer=observer;self.observer_failures=0

    def __getattr__(self,name):return getattr(self.raw,name)

    def execute(self,query,parameters=()):
        failure=None
        statement=query if isinstance(query,str) else 'COMPOSED'
        identity={'statement_id':hashlib.sha256(statement.encode()).hexdigest()[:16],
                  'operation':statement.split(None,1)[0].upper() if statement.strip() else 'EMPTY'}
        self.notify(dict(identity,active=True,elapsed_seconds=0.,sqlstate=None))
        started=self.clock()
        try:return self.raw.execute(query,parameters)
        except Exception as exc:
            failure=exc;raise
        finally:
            # Diagnostics must never replace the original result/exception.
            record=dict(identity,elapsed_seconds=round(max(0.,self.clock()-started),6),
                        sqlstate=getattr(failure,'sqlstate',None))
            self.recent.append(record)
            self.notify(dict(record,active=False))

    def notify(self,value):
        if self.observer is not None:
            try:self.observer(value)
            except Exception:self.observer_failures+=1

    def metrics(self):return list(self.recent)
