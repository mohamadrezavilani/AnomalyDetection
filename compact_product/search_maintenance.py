"""Bounded online index preparation diagnostics; no worker or evidence mutations."""
import threading
import time


def configure_wait(db, seconds=900):
    if not isinstance(seconds, int) or not 30 <= seconds <= 3600:
        raise ValueError('SEARCH_STATEMENT_TIMEOUT_OUT_OF_RANGE')
    # Concurrent builds must wait for writers and old snapshots. A short lock
    # timeout also interrupts these normal waits. Bound each entire DDL statement
    # instead, only on this dedicated preparation connection.
    db.execute("SELECT set_config('statement_timeout',%s,false)",(str(seconds*1000),))
    db.execute('SET lock_timeout=0')


def progress_snapshot(db, pid):
    # No query text, connection strings, payloads or client addresses exported.
    return db.execute('''SELECT a.state,a.wait_event_type,a.wait_event,
        pg_blocking_pids(a.pid) AS blocking_pids,p.phase,
        p.lockers_total,p.lockers_done,p.current_locker_pid,
        p.blocks_total,p.blocks_done,p.tuples_total,p.tuples_done
        FROM pg_stat_activity a LEFT JOIN pg_stat_progress_create_index p USING(pid)
        WHERE a.pid=%s''',(pid,)).fetchone()


class ProgressMonitor:
    def __init__(self, factory, pid, emit, interval=15):
        self.factory=factory;self.pid=pid;self.emit=emit;self.interval=interval
        self.done=threading.Event();self.stage='PREPARING';self.last=None
        self.started=time.monotonic();self.thread=None

    def set_stage(self, stage):
        self.stage=stage
        self.emit(dict(status='COMPACT_SEARCH_INDEX_PREPARING',stage=stage,
                       elapsed_seconds=round(time.monotonic()-self.started,1)))

    def _observe(self):
        db=None
        try:
            db=self.factory()
            db.conn.execute('SET statement_timeout=3000')
            db.conn.execute('SET default_transaction_read_only=on')
            while not self.done.wait(self.interval):
                self.last=progress_snapshot(db.conn,self.pid)
                self.emit(dict(status='COMPACT_SEARCH_INDEX_PROGRESS',stage=self.stage,
                    elapsed_seconds=round(time.monotonic()-self.started,1),database=self.last))
        except Exception as exc:
            self.emit(dict(status='COMPACT_SEARCH_INDEX_PROGRESS_UNAVAILABLE',
                           failure_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None)))
        finally:
            if db is not None:db.close()

    def __enter__(self):
        self.thread=threading.Thread(target=self._observe,daemon=True)
        self.thread.start();return self

    def __exit__(self, *exc):
        self.done.set();self.thread.join(timeout=14)
