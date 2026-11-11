"""Reserved profile/model work; a failed sub-lane cannot suppress the others."""
from .process_control import safe_failure
from .history_scope import effective_floor


def step(store,source,clock,cycle,state):
    if not callable(getattr(source,'profile',None)):return
    from .scenario_store import seed,next_profile,save_profile,process_one
    errors=state.setdefault('scenario_lane_failures',{});due=state.setdefault('scenario_lane_retry_ns',{})
    def attempt(name,call):
        if due.get(name,0)>clock.time_ns():return
        state['scenario_phase']=name
        try:call();errors.pop(name,None)
        except Exception as exc:
            errors[name]={'phase':name,'failure':safe_failure(exc),'at_ns':clock.time_ns()}
            state['scenario_failures_total']=state.get('scenario_failures_total',0)+1
            due[name]=clock.time_ns()+30_000_000_000
    if cycle%4==1:attempt('seed_profile_work',lambda:seed(store,clock.time_ns()))
    if cycle%4==3:
        from .longitudinal import seed as seed_longitudinal,upgrade_profiles
        from .scenario_store import upgrade_methods
        attempt('upgrade_scenario_methods',lambda:upgrade_methods(store))
        attempt('upgrade_case_content',lambda:upgrade_profiles(store))
        attempt('seed_longitudinal_content',lambda:seed_longitudinal(store))
    def sample():
        from .service_sampling import read,apply
        lane='service_sample_old_cursor' if cycle%8==6 else 'service_sample_fresh_cursor'
        packet=read(source,store.state(lane));state['last_service_sample']=apply(store,packet,lane)
        if lane=='service_sample_old_cursor' and packet['status']=='CAUGHT_UP':store.save_state(lane,{'next_ns':effective_floor(packet['source'])})
    if cycle%4==2:attempt('sample_service_requests',sample)
    def profiles():
        until=clock.monotonic()+1.0
        for turn in range(4):
            key=next_profile(store,clock.time_ns(),independent=turn==0 and cycle%4==0,
                historical=turn==0 and cycle%4==2)
            if not key:break
            try:save_profile(store,source.profile(key),clock.time_ns())
            except Exception:
                store.raw.execute('UPDATE anomaly_detection.adp_profile_tasks SET due_ns=%s,attempts=attempts+1 WHERE request_key=%s',(clock.time_ns()+60_000_000_000,key));raise
            state['content_reads']=state.get('content_reads',0)+1
            if clock.monotonic()>=until:break
    attempt('read_request_content',profiles)
    def model():
        store.active_scenario_scope=None
        try:outcome=process_one(store,clock.time_ns())
        except Exception:
            active=getattr(store,'active_scenario_scope',None)
            if active:store.raw.execute('UPDATE anomaly_detection.adp_scenario_jobs SET due_ns=%s,claimed_version=0 WHERE scope_key=%s AND dirty=TRUE',(clock.time_ns()+30_000_000_000,active))
            raise
        if outcome:
            results=state.setdefault('scenario_results',{});status=outcome['status'];results[status]=results.get(status,0)+1
            state['scenario_evaluations']=state.get('scenario_evaluations',0)+int(outcome['status']=='APPLIED')
            state['last_scenario_scope']=outcome.get('scope_key')
    attempt('evaluate_content_network',model)
    def traffic():
        from .scenario_traffic import read_page,apply
        lane='scenario_old_traffic_cursor' if cycle%16==9 else 'scenario_traffic_cursor'
        cursor=store.state(lane);until=clock.monotonic()+1.5
        try:
            for _ in range(4):
                packet=read_page(source,cursor,oldest=cycle%16==9);state['last_technical_census']=apply(store,packet,cursor_name=lane)
                if cycle%16==9 and packet['status']=='CAUGHT_UP':store.save_state(lane,{})
                cursor=store.state(lane)
                if state['last_technical_census']!='PAGE' or clock.monotonic()>=until:break
        except Exception as exc:
            if getattr(exc,'sqlstate',None)=='57014':
                cursor=store.state(lane);cursor['page_size']=max(64,int(cursor.get('page_size',1024))//2);store.save_state(lane,cursor)
            raise
    if cycle%8==1:attempt('read_technical_request_census',traffic)
    state['last_scenario_failure']=max(errors.values(),key=lambda x:x['at_ns']) if errors else None
    state['scenario_queue_activity']=getattr(store,'scenario_queue_activity',{})
