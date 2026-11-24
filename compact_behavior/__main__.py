"""Small prototype gate: file/ES -> compact PostgreSQL, without legacy runtime."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import threading
import time
import tracemalloc
from . import CONTRACT,EXTRACTOR,FEATURES,FIVE
from .extract import Extractor,Limits,instant,iso,digest
from .source import settings,WindowFile,ElasticWindow,retryable_source_failure
from .store import Store


def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.tmp')
    temp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    for attempt in range(30):
        try:os.replace(temp,path);break
        except PermissionError:
            if attempt==29:raise
            time.sleep(.01)


def process_info():
    if os.name!='nt':
        import resource
        return dict(process_pid=os.getpid(),process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)
    import ctypes
    from ctypes import wintypes
    class Memory(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[(k,ctypes.c_size_t) for k in (
            'PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
            'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);psapi=ctypes.WinDLL('psapi',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE;handle=kernel.GetCurrentProcess()
    memory=Memory();memory.cb=ctypes.sizeof(memory)
    psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Memory),wintypes.DWORD]
    ok=psapi.GetProcessMemoryInfo(handle,ctypes.byref(memory),memory.cb)
    created=wintypes.FILETIME();exited=wintypes.FILETIME();cpu1=wintypes.FILETIME();cpu2=wintypes.FILETIME()
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4
    if not kernel.GetProcessTimes(handle,ctypes.byref(created),ctypes.byref(exited),ctypes.byref(cpu1),ctypes.byref(cpu2)):
        raise OSError('process_identity_unavailable')
    value=(created.dwHighDateTime<<32)|created.dwLowDateTime
    return dict(process_pid=os.getpid(),process_created_epoch_seconds=value/10_000_000-11644473600,
                process_peak_rss_bytes=memory.PeakWorkingSetSize if ok else None)


def notice(status,**kwargs):print(json.dumps(dict(status=status,**kwargs),ensure_ascii=True),flush=True)


def measure_window(store,stream,source,*,progress=None):
    began=time.monotonic();cpu=time.process_time();last=began;attempts=[]
    source_deadline=began+source.budget if isinstance(source,ElasticWindow) else None
    while True:
        extractor=Extractor(store.limits);iterator=source.records();attempt_started=time.monotonic()
        if source_deadline is not None:source.budget=max(.1,source_deadline-time.monotonic())
        try:
            for record in iterator:
                extractor.add(record)
                if progress and time.monotonic()-last>5:
                    progress(records=extractor.records,requests=len(extractor.states),elapsed_seconds=round(time.monotonic()-began,2));last=time.monotonic()
        except Exception as exc:
            attempts.append(dict(status='DISCARDED_INCOMPLETE_ATTEMPT',page_size=getattr(source,'page_size',None),
                source_records_discarded=extractor.records,seconds=time.monotonic()-attempt_started,
                failure={'type':type(exc).__name__,'code':str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None,
                    'http_status':getattr(exc,'code',None),'details':getattr(exc,'details',None)}))
            exc.source_attempts=attempts
            if source_deadline is None or not retryable_source_failure(exc) or len(attempts)>=3 or time.monotonic()>=source_deadline:
                raise
            source.page_size=max(64,source.page_size//4)
            notice('COMPACT_SOURCE_RETRY',attempt=len(attempts)+1,page_size=source.page_size,
                   discarded_records=extractor.records,reason=attempts[-1]['failure'])
            time.sleep(.2*len(attempts))
        else:
            attempts.append(dict(status='COMPLETE',page_size=getattr(source,'page_size',None),
                source_records=extractor.records,seconds=time.monotonic()-attempt_started));break
        finally:iterator.close()
    states=extractor.finish();read_extract=time.monotonic()-began
    begin=instant(source.metadata['window_start']);end=instant(source.metadata['window_end'])
    if begin%FIVE or end-begin!=FIVE:raise ValueError('aligned_window_required')
    result=store.publish(stream,begin,end,states,extractor.records)
    statistics=result.pop('packet_statistics',None)
    if statistics is None:
        # Compatibility with read-only/test publishers that do not use Store.
        from .statistics import PacketStatistics
        from .extract import materialize
        packet=PacketStatistics()
        for state in states.values():packet.observe(materialize(stream,state))
        statistics=packet.result()
    elapsed=time.monotonic()-began
    result.update(read_extract_seconds=read_extract,source_request_decode_seconds=getattr(source,'network_seconds',None),
        source_attempts=attempts,source_page_size=getattr(source,'page_size',None),
        source_completeness={k:source.metadata[k] for k in ('complete','count','expected_count','method','pages',
            'completeness_basis','terminal_empty_page','unique_documents','identity_bytes','scroll_early_terminated_pages') if k in source.metadata},
        source_response_diagnostics=getattr(source,'response_diagnostics',[]),
        source_timer_scope='HTTP_REQUEST_BODY_READ_AND_JSON_DECODE_INCLUDING_CURSOR_CLEANUP',
        read_decode_extract_seconds_includes_network=True,total_seconds=elapsed,client_cpu_seconds=time.process_time()-cpu,
        extraction_state_bytes=extractor.state_bytes,missing_request_ids=extractor.missing_request_ids,
        **statistics,
        statistics_scope='CURRENT_INPUT_PACKET_NOT_UNIQUE_HISTORY_OR_ALL_MERGED_LATE_STATES')
    return result


def run(args):
    stream=args.stream
    report=dict(status='STARTING',contract=CONTRACT,extractor=EXTRACTOR,features=FEATURES,schema=args.schema,
        windows=[],legacy_runtime_used=False,legacy_tables_read_or_written=False,raw_logs_stored=False,
        ad_executed=False,web_executed=False,production_capacity_acceptance='NOT_ASSIGNED',
        full_method_acceptance='NOT_ASSIGNED',measurement_includes_tracemalloc=args.trace_memory,
        server_measurement_required=True,command_token=getattr(args,'trial_token',None),**process_info())
    save(args.output,report)
    if args.trace_memory:tracemalloc.start()
    store=None;active_source=None;began=time.monotonic();done=threading.Event()
    def heartbeat():
        while not done.wait(15):notice('COMPACT_PROTOTYPE_RUNNING',elapsed_seconds=round(time.monotonic()-began),committed_windows=len(report['windows']))
    thread=threading.Thread(target=heartbeat,daemon=True);thread.start()
    try:
        from .version import verify
        report['package']=verify()
        cfg=settings(args.config)
        store=Store(cfg['DATABASE'],schema=args.schema);store.init()
        report['postgres_version']=store.conn.execute('SHOW server_version').fetchone()['server_version']
        report['database']=store.conn.info.dbname
        report['server_settings']=[dict(r) for r in store.conn.execute("SELECT name,setting,unit FROM pg_settings WHERE name=ANY(%s) ORDER BY name",
            (['shared_buffers','work_mem','fsync','synchronous_commit','full_page_writes'],)).fetchall()]
        if args.files:
            if not stream:raise ValueError('explicit_stream_required_for_file_inputs')
            sources=[WindowFile(p) for p in args.files]
        else:
            elastic=cfg.get('ELASTICSEARCH')
            if not isinstance(elastic,dict):raise ValueError('literal_ELASTICSEARCH_required')
            stream=stream or ElasticWindow(elastic,0,FIVE).namespace
            begin=store.cursor(stream)
            finish=(time.time_ns()-60_000_000_000)//FIVE*FIVE
            if begin is None:
                begin=instant(args.start) if args.start else finish-args.windows*FIVE
            elif args.start and instant(args.start)!=begin:raise ValueError('existing_compact_stream_resumes_own_checkpoint')
            if begin+args.windows*FIVE>finish:raise ValueError('not_enough_closed_source_windows_yet')
            sources=[ElasticWindow(elastic,begin+i*FIVE,begin+(i+1)*FIVE,page_size=elastic.get('compact_page_size',500)) for i in range(args.windows)]
        report['stream_id']=stream;report['storage_before']=store.measure();save(args.output,report)
        def progress(**values):
            if getattr(args,'stop_file',None) and args.stop_file.exists():raise InterruptedError('prototype_stop_requested')
            notice('COMPACT_EXTRACTING',**values)
        for source in sources:
            active_source=source
            if isinstance(source,ElasticWindow):
                report['active_window']={'start_ns':source.start,'end_ns':source.end,'method':'elasticsearch'}
                save(args.output,report)
            progress()
            result=measure_window(store,stream,source,progress=progress)
            report['windows'].append(result);save(args.output,report)
            notice('COMPACT_WINDOW_MEASURED',start=iso(result['start_ns']),fresh=result['fresh_publication'],
                source_records=result['source_records'],inserted=result['inserted'],updated=result['updated'],
                seconds=round(result['total_seconds'],3))
        report['storage_after']=store.measure();report['checkpoint_next_ns']=store.cursor(stream)
        report['status']='COMPACT_PROTOTYPE_MEASURED' if any(w['observed_public_api_requests'] for w in report['windows']) else 'COMPACT_PROTOTYPE_EMPTY_SOURCE'
    except BaseException as exc:
        report['status']='COMPACT_PROTOTYPE_INCOMPLETE'
        # Do not put source message bodies, credentials, URLs or arbitrary SQL exceptions in receipts.
        report['failure']=dict(type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None,
                               sqlstate=getattr(exc,'sqlstate',None),details=getattr(exc,'details',None),
                               source_attempts=getattr(exc,'source_attempts',[]))
        if active_source is not None:report['source_response_diagnostics']=getattr(active_source,'response_diagnostics',[])
    finally:
        if store:store.close()
        done.set();thread.join(1)
        report['elapsed_seconds']=time.monotonic()-began
        report.update(process_info())
        if args.trace_memory:
            _,peak=tracemalloc.get_traced_memory();report['python_allocated_peak_bytes']=peak;tracemalloc.stop()
        new=[w for w in report['windows'] if w['fresh_publication']]
        seconds=sum(w['total_seconds'] for w in new)
        report['fresh_window_observed_rate_per_hour']=len(new)*3600/seconds if seconds else None
        report['fresh_windows']=len(new);report['reprocessed_windows']=len(report['windows'])-len(new)
        report['rate_excludes_schema_setup_and_role_control']=True
        save(args.output,report);notice(report['status'],output=str(args.output),fresh_windows=len(new))
    return report


def parser():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True)
    p.add_argument('--schema',default='p24_compact');p.add_argument('--stream');p.add_argument('--start')
    p.add_argument('--files',type=Path,nargs='+');p.add_argument('--windows',type=int,choices=range(1,5),default=3)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--trace-memory',action='store_true')
    p.add_argument('--stop-file',type=Path);p.add_argument('--trial-token')
    return p


if __name__=='__main__':
    result=run(parser().parse_args());raise SystemExit(0 if result['status']=='COMPACT_PROTOTYPE_MEASURED' else 2)
