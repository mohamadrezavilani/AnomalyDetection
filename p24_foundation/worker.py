"""Finite, resumable projection-queue worker for disposable design databases."""
from __future__ import annotations

import threading
import time

from .config import connect
from .errors import FoundationError
from .store import floor_ns


class ProjectionWorker:
    """Claim and execute one fenced projection item at a time.

    The projection transaction can outlive its lease. A separate connection
    renews the lease while that transaction runs; if renewal loses the fence,
    completion is rejected and the immutable result remains an unreferenced
    historical run rather than overwriting newer work.
    """

    def __init__(self, store, database, *, lease_seconds=120):
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 10 <= lease_seconds <= 300:
            raise FoundationError("invalid_lease_duration")
        self.store = store
        self.database = database
        self.lease_seconds = lease_seconds
        self.heartbeat_interval_seconds = max(2.0, min(30.0, lease_seconds / 3.0))

    def _heartbeat_once(self, claim):
        # Do not construct another FoundationStore here: its namespace setup
        # takes the same advisory lock held by the long projection transaction.
        with connect(self.database) as connection:
            with connection.transaction():
                row = connection.execute("""UPDATE p24_next.foundation_work_item
                    SET lease_until=clock_timestamp()+(%s*interval '1 second'),updated_at=clock_timestamp()
                    WHERE namespace_id=%s AND work_id=%s AND state='leased'
                      AND lease_owner=%s AND lease_generation=%s AND lease_until>clock_timestamp()
                    RETURNING work_id""",
                    (self.lease_seconds, self.store.namespace_id, claim["work_id"],
                     claim["worker"], claim["lease_generation"])).fetchone()
                if not row:
                    return False
                connection.execute("""INSERT INTO p24_next.foundation_work_attempt
                    (namespace_id,work_id,lease_generation,action,worker_claim)
                    VALUES(%s,%s,%s,'renewed',%s)""",
                    (self.store.namespace_id, claim["work_id"], claim["lease_generation"], claim["worker"]))
        return True

    def run_once(self, worker):
        claims = self.store.claim_work(worker, limit=1, lease_seconds=self.lease_seconds)
        if not claims:
            return dict(status="idle", claimed=0)
        claim = claims[0]
        lost = threading.Event()
        stop = threading.Event()
        interval = self.heartbeat_interval_seconds

        def heartbeat_loop():
            while not stop.wait(interval):
                try:
                    if not self._heartbeat_once(claim):
                        lost.set()
                        return
                except Exception:
                    # A transient connection failure is retried on the next
                    # tick; the database lease itself remains the authority.
                    continue

        heartbeat = threading.Thread(target=heartbeat_loop, name="p24-projection-lease", daemon=True)
        heartbeat.start()
        try:
            payload = claim["payload"]
            source_ids = payload["source_snapshot_ids"]
            event_cutoff = floor_ns(int(payload["event_cutoff_ns"])).isoformat()
            knowledge_at = floor_ns(int(payload["knowledge_at_ns"])).isoformat()
            result = self.store.project(source_ids, event_cutoff=event_cutoff,
                                        knowledge_at=knowledge_at, mode=payload["mode"])
            completed = self.store.complete_work(claim["work_id"], worker,
                                                 claim["lease_generation"], result["run_id"])
            return dict(status="completed" if completed else "lease_lost",
                        claimed=1, completed=completed, work_id=claim["work_id"],
                        run_id=result["run_id"], heartbeat_lost=lost.is_set())
        except FoundationError:
            try:
                state = self.store.fail_work(claim["work_id"], worker, claim["lease_generation"],
                                             error_code="projection_rejected", retryable=False)
            except Exception:
                state = False
            return dict(status="dead" if state == "dead" else "lease_lost",
                        claimed=1, work_id=claim["work_id"], error="projection_rejected")
        except Exception as error:
            # Only database-driver errors are retryable. Arbitrary programming
            # errors are dead-lettered with a fixed safe code and no traceback.
            try:
                import psycopg
                retryable = isinstance(error, psycopg.Error)
            except Exception:
                retryable = False
            delay = min(300, 2 ** min(int(claim["attempt"]), 8))
            try:
                state = self.store.fail_work(claim["work_id"], worker, claim["lease_generation"],
                                             error_code="projection_runtime_error",
                                             retryable=retryable, delay_seconds=delay if retryable else 0)
            except Exception:
                state = False
            public_status = state if state in {"retry", "dead"} else "lease_lost"
            return dict(status=public_status, claimed=1, work_id=claim["work_id"],
                        error="projection_runtime_error", retryable=retryable)
        finally:
            stop.set()
            heartbeat.join(timeout=2)

    def run_bounded(self, worker, *, max_items, max_runtime_seconds, poll_seconds=2):
        if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= 10000:
            raise FoundationError("invalid_worker_item_limit")
        if isinstance(max_runtime_seconds, bool) or not isinstance(max_runtime_seconds, int) or not 1 <= max_runtime_seconds <= 3600:
            raise FoundationError("invalid_worker_runtime_limit")
        if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, int) or not 1 <= poll_seconds <= 60:
            raise FoundationError("invalid_worker_poll_interval")
        deadline = time.monotonic() + max_runtime_seconds
        outcomes = []
        idle_polls = 0
        while len(outcomes) < max_items and time.monotonic() < deadline:
            outcome = self.run_once(worker)
            if outcome["status"] == "idle":
                idle_polls += 1
                time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))
                continue
            outcomes.append(outcome)
        return dict(status="finished", processed=len(outcomes), idle_polls=idle_polls,
                    outcomes=outcomes, bounded=True)
