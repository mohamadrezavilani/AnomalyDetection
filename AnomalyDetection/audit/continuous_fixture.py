"""Complete continuous.evaluate dispatch with explicitly SCRIPTED SQL inputs.

The reference is independently specified: 400 other actors, two executions
one nanosecond apart per actor, across >24h of complete source coverage.
This is not SQL-engine, native Worker or production qualification.
"""
from contextlib import nullcontext
from anomaly_detection import FIVE_NS as W
from anomaly_detection.snapshot import canonical
from anomaly_detection.continuous import evaluate
from .request_sample_fixture import Result,T,S

ACTOR='a'*64
DAY=288*W


class Store:
    def __init__(self,n=20,missing=False,stale=False,offset=-5):
        self.raw=self;self.n=n;self.missing=missing;self.stale=stale;self.offset=offset;self.rolling_cache={};self.statements=[]
    def transaction(self):return nullcontext()
    def execute(self,sql,args=()):
        self.statements.append(sql)
        if sql.startswith('SELECT start_ns,source,complete FROM anomaly_detection.adp_source_windows'):
            return Result([dict(start_ns=at,source={'peer_population_valid':True},complete=not(self.missing and at==T-W))
                for at in range(T-21*DAY,T+W,W)])
        if sql.startswith('INSERT INTO anomaly_detection.adp_peer_epochs'):return Result()
        if sql.startswith('SELECT version FROM anomaly_detection.adp_peer_epochs'):return Result([{'version':1}])
        if sql.startswith('SELECT f.request_key,f.at_ns,f.details,f.revision,f.anchor_key'):
            data=[]
            for i in range(self.n):
                key=f'{i:064x}';anchor='ba1:'+key
                fact=dict(source_present=True,quality={'evidence_available':True,'conflicted':False},
                    semantic={'state':'active','revision':1,'anchor_key':anchor})
                data.append(dict(request_key=key,at_ns=T+self.offset+i,details=canonical(fact),revision=2 if self.stale else 1,anchor_key=anchor))
            return Result(data)
        if sql.startswith('WITH events AS') and 'FROM maxima ORDER BY session_key LIMIT 10001' in sql:
            # For every tested duration, each peer's exact event-aligned peak is
            # two, since its only two events are adjacent nanoseconds.
            peers=[dict(session_key=f'peer-{i:04d}',value=2,low_ns=T-(288+i)*W+1,high_ns=T-(288+i)*W+2) for i in range(400)]
            # The same-actor historical prefix must be excluded by real code.
            own=min(self.n,max(0,-self.offset))
            if own:peers.append(dict(session_key=ACTOR,value=own,low_ns=T+self.offset,high_ns=T+self.offset+own-1))
            return Result(peers)
        raise AssertionError('Unknown scripted continuous query: '+sql[:100])


def run_continuous(n=20,missing=False,stale=False):
    store=Store(n,missing,stale)
    context={'windows':[{'start_ns':T,'counts':{S:max(0,n-5)}}]}
    decisions,inputs=evaluate(store,{'session_key':ACTOR,'target_ns':T},context)
    return decisions,inputs,store
