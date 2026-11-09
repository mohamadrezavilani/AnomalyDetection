"""One read-only capture ahead; all database work stays on the publisher thread."""
from __future__ import annotations

from dataclasses import dataclass,field
from pathlib import Path
import threading
import time

from .viewer_online import checked_window


@dataclass
class _Job:
    start:int
    end:int
    began:float
    done:threading.Event=field(default_factory=threading.Event)
    cancel:threading.Event=field(default_factory=threading.Event)
    path:Path|None=None
    seconds:float=0
    failed:bool=False


class OneWindowPrefetch:
    """Process-local, bounded queue of immutable captures, never a checkpoint.

    Only closed windows are eligible. Rechecks bypass this queue. A capture
    older than five minutes is fetched afresh; restart never adopts old files.
    The capture callable must support cooperative cancel_event for background
    calls. In-flight HTTP remains bounded by its existing request timeout.
    """
    def __init__(self,capture,*,max_age_seconds=300,clock=time.monotonic):
        if not 1<=max_age_seconds<=300:raise ValueError('invalid_prefetch_age')
        self.capture=capture;self.max_age=max_age_seconds;self.clock=clock
        self.job=None;self.closed=False

    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    def prepare(self,start,end,*,closed_ns):
        checked_window(start,end)
        if self.closed or end>closed_ns:return False
        if self.job is not None:
            if self.job.cancel.is_set() and self.job.done.is_set():self.job=None
            else:return False
        job=_Job(start,end,self.clock());self.job=job
        def fetch():
            try:job.path=Path(self.capture(start,end,cancel_event=job.cancel))
            except Exception:job.failed=True  # Never retain raw driver/config errors.
            finally:
                job.seconds=self.clock()-job.began;job.done.set()
        # A stalled network request must not keep a stopped publisher alive.
        # Cooperative cancellation still closes PIT/scroll and partial files.
        threading.Thread(target=fetch,name='viewer-one-window-capture',daemon=True).start()
        return True

    def cancel(self):
        if self.job is not None:self.job.cancel.set()

    def close(self):
        self.closed=True;self.cancel()
        if self.job is not None:self.job.done.wait(timeout=1)

    def take(self,start,end):
        checked_window(start,end)
        if self.closed:raise ValueError('prefetch_closed')
        began=self.clock();job=self.job;reason=None
        if job is not None:
            if (job.start,job.end)!=(start,end):reason='different_window'
            else:
                while not job.done.is_set() and not job.cancel.is_set():
                    left=self.max_age-(self.clock()-job.began)
                    if left<=0:break
                    job.done.wait(timeout=min(.1,left))
                age=self.clock()-job.began
                if age>self.max_age or not job.done.is_set():reason='stale'
                elif job.cancel.is_set():reason='cancelled'
                elif job.failed:reason='background_capture_failed'
                else:
                    self.job=None
                    return dict(path=job.path,capture_seconds=job.seconds,
                                capture_wait_seconds=self.clock()-began,prefetched=True,
                                prefetch_age_seconds=age,prefetch_discard_reason=None)
            job.cancel.set()
            if job.done.is_set():self.job=None
        # One fresh attempt after a discarded/failed prefetch. Normal capture
        # validation and the unchanged worker/test deadlines remain mandatory.
        fresh_began=self.clock();path=self.capture(start,end)
        return dict(path=path,capture_seconds=self.clock()-fresh_began,
                    capture_wait_seconds=self.clock()-began,prefetched=False,
                    prefetch_age_seconds=0,prefetch_discard_reason=reason)
