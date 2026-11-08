from .sql_budget import statement_budget
"""Optional owned statistics cannot gate ingestion or detection.

Each section has a short local statement limit and an independent savepoint.
Unknown values remain unknown; a cached value carries its original timestamp.
No counters, queues, models or source state are written by this reader.
"""
from copy import deepcopy
import time
from .process_control import safe_failure


def collect(store,sections,*,clock=None,seconds=1.0,statement_ms=200):
    clock=clock or time.monotonic;began=clock();deadline=began+seconds
    cache=getattr(store,'statistics_cache',{})
    store.statistics_cache=cache
    values={};quality={}
    for name,reader in sections:
        old=cache.get(name)
        status='DEFERRED_BUDGET';failure=None
        if clock()<deadline:
            try:
                # Plain transaction/savepoint: no application writer lock.
                # LOCAL automatically restores the connection's normal budget.
                with statement_budget(store.raw,max(1,int(statement_ms))):
                    value=reader()
                old={'value':deepcopy(value),'observed_ns':time.time_ns()}
                cache[name]=old;status='CURRENT'
            except Exception as exc:
                if getattr(exc,'sqlstate',None)!='57014':raise
                failure=safe_failure(exc);status='CACHED_AFTER_TIMEOUT' if old else 'UNAVAILABLE_TIMEOUT'
        elif old:status='CACHED_BUDGET'
        values[name]=deepcopy(old['value']) if old else None
        quality[name]={'status':status,'observed_ns':old['observed_ns'] if old else None}
        if failure:quality[name]['failure']=failure
    meta={'status':'COMPLETE' if all(v['status']=='CURRENT' for v in quality.values()) else 'PARTIAL',
        'sections':quality,'elapsed_seconds':round(max(0.,clock()-began),6),
        'statement_limit_ms':statement_ms,'start_budget_seconds':seconds,
        'missing_values_are_zero':False,'source_reads':0}
    return values,meta
