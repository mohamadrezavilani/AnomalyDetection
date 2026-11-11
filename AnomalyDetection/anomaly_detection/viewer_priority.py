"""Cooperative disk admission: Viewer publication first, bounded AD fairness.

No source locks or settings are changed. Jobs stay pending while deferred;
one ordinary AD cycle every 30 seconds prevents permanent starvation during
continuous Viewer catch-up. Free Viewer intervals admit normal AD processing.
"""
BUSY_SQL = """SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
    WHERE locktype='advisory' AND classid=240026 AND objid=2 AND objsubid=2
      AND mode='ExclusiveLock' AND granted
      AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())) AS busy"""


class ViewerPriority:
    def __init__(self):
        self.next_probe=0.;self.next_slice=0.;self.busy=False;self.observed=False;self.slice_active=False

    def admit(self,source,clock):
        probe=getattr(source,'viewer_writer_busy',None)
        now=clock.monotonic()
        if self.slice_active:
            # The cooldown begins after the admitted cycle has finished, even
            # if one slow cycle itself consumed more than thirty seconds.
            self.next_slice=now+30;self.slice_active=False
        if not callable(probe):return {'admitted':True,'mode':'NO_VIEWER_PROBE'}
        if now>=self.next_probe:
            try:self.busy=bool(probe())
            except Exception:
                self.observed=False;self.next_probe=now+30
                raise
            self.next_probe=now+1
            if not self.observed:self.next_slice=now+30
            self.observed=True
        if not self.observed:return {'admitted':True,'mode':'PROBE_UNAVAILABLE'}
        if not self.busy:
            self.next_slice=now+30
            return {'admitted':True,'writer_busy':False,'mode':'VIEWER_IDLE'}
        if now>=self.next_slice:
            self.next_slice=now+30;self.slice_active=True
            return {'admitted':True,'writer_busy':True,'mode':'BOUNDED_FAIRNESS_CYCLE'}
        return {'admitted':False,'writer_busy':True,'mode':'WAITING_FOR_VIEWER_PUBLICATION',
                'next_slice_seconds':round(self.next_slice-now,3)}
