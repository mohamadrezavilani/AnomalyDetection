"""Bounded SQL timing for the owned connection; no statement or parameters.

Fingerprints identify fixed source statements, not user data. Cursor bulk
writes remain delegated; the trace does not claim coverage of their timing.
"""
from collections import deque
import hashlib
import time


class ObservedConnection:
    def __init__(self,raw,clock=None):
        self.raw=raw;self.clock=clock or time.monotonic;self.recent=deque(maxlen=16)

    def __getattr__(self,name):return getattr(self.raw,name)

    def execute(self,query,parameters=()):
        started=self.clock();failure=None
        try:return self.raw.execute(query,parameters)
        except Exception as exc:
            failure=exc;raise
        finally:
            # Diagnostics must never replace the original result/exception.
            statement=query if isinstance(query,str) else 'COMPOSED'
            self.recent.append({'statement_id':hashlib.sha256(statement.encode()).hexdigest()[:16],
                'operation':statement.split(None,1)[0].upper() if statement.strip() else 'EMPTY',
                'elapsed_seconds':round(max(0.,self.clock()-started),6),
                'sqlstate':getattr(failure,'sqlstate',None)})

    def metrics(self):return list(self.recent)
