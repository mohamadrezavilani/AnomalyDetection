"""Keep reserved evaluation turns even when one evaluation exhausts a batch.

Volume is scheduling priority only, never an anomaly threshold. The existing
finite ready pass and all-age history lanes remain separate from the live lane.
"""
class EvaluationScheduler:
    LANES = ('live', 'recheck', 'ready', 'history', 'live', 'candidate',
             'evidence', 'recheck', 'live', 'reference', 'ready', 'history',
             'backlog', 'recheck', 'evidence', 'history')

    def __init__(self):
        self.turn = 0

    def choose(self, store, now):
        lane = self.LANES[self.turn % len(self.LANES)]
        self.turn += 1
        job = None
        if lane == 'live':
            job = store.next_live_job(now)
        elif lane == 'backlog':
            job = store.next_backlog_job(now)
        elif lane == 'candidate':
            job = store.next_candidate_job(now)
        elif lane == 'evidence':
            from .product_priority import next_evidence_job
            job = next_evidence_job(store, now)
        elif lane == 'ready':
            job = store.next_ready_job(now)
        elif lane == 'recheck':
            method=getattr(store,'next_recheck_job',None)
            job=method(now) if method else store.next_job(now,recheck=True)
        elif lane == 'reference':
            if callable(getattr(store,'next_model_job',None)):
                job=store.next_model_job(now)
                if job is not None:return job,'advanced'
            from .service_reference import next_case
            job = next_case(store, now)
        else:
            job = store.next_job(now, recent=False)
        if job is not None:
            return job, lane
        # Empty reserved lanes lend their turn without losing the next turn.
        job = store.next_live_job(now)
        if job is not None:
            return job, 'live'
        job = store.next_ready_job(now)
        if job is not None:
            return job, 'ready'
        return store.next_job(now, recent=False), 'history'
