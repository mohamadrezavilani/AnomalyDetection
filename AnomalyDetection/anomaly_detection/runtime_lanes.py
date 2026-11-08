"""Optional owned maintenance has independent retry slots, never a new source gate."""
from .process_control import safe_failure


def maintenance(store,clock,cycle,state):
    from .job_scope import warm as scope_warm,promote_observed
    from .cases import backfill,requalify
    from .population import warm as population_warm
    from .review_policy import warm as history_warm
    from .service_reference import warm_one
    from .product_priority import warm as priority_warm
    def scope():
        value=scope_warm(store)
        if not value.get('done'):state['scope_observed_promotions']=promote_observed(store)
        return value
    def previous():
        value=store.state('previous_import')
        return value if value.get('done') else store.import_previous()
    tasks=[('job_scope_backfill',scope),('case_migration',lambda:backfill(store)),
        ('review_policy_migration',lambda:requalify(store,clock.time_ns())),
        ('population_backfill',lambda:population_warm(store)),('previous_import',previous)]
    if cycle%16==1:tasks.append(('rate_history_requalification',lambda:history_warm(store)))
    if cycle%4==0:tasks += [('service_reference_warm',lambda:warm_one(store)),('live_priority_warm',lambda:store.warm_live_priorities()),('evidence_priority_backfill',lambda:priority_warm(store,clock.time_ns()))]
    failures=state.setdefault('maintenance_failures',{});due=state.setdefault('maintenance_retry_ns',{})
    for name,call in tasks:
        if due.get(name,0)>clock.time_ns():continue
        state['phase']='maintenance_'+name
        try:state[name]=call();failures.pop(name,None)
        except Exception as exc:
            if getattr(exc,'sqlstate',None)!='57014':raise
            failures[name]={'failure':safe_failure(exc),'at_ns':clock.time_ns(),'queries':store.raw.metrics() if callable(getattr(store.raw,'metrics',None)) else []}
            due[name]=clock.time_ns()+30_000_000_000
