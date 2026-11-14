"""Durable missing-window replay without rewinding the published high-watermark."""
from datetime import date,datetime,time
from pathlib import Path
from zoneinfo import ZoneInfo
import time as clock
import uuid
from p24_foundation.viewer_online import FIVE_NS,publish_capture,iso

TABLE='public.viewer_history_replay_state'


def boundary(day):
    value=date.fromisoformat(day)
    if value.isoformat()!=day:raise ValueError('invalid_history_date')
    return int(datetime.combine(value,time.min,ZoneInfo('Asia/Tehran')).timestamp())*1_000_000_000


class HistoryReplay:
    def __init__(self,db,day):
        self.db=db;self.day=day;self.begin=boundary(day)

    def initialize(self):
        db=self.db
        state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
        if not state or not state['start_ns']<=self.begin<=state['next_ns']:
            raise ValueError('history_date_outside_existing_stream')
        retained=db.one("SELECT to_regclass('public.viewer_retention_audit') AS present") if not db.sqlite else None
        if retained and retained['present']:
            row=db.one('SELECT MAX(cutoff_ns) AS cutoff FROM public.viewer_retention_audit')
            if row and row['cutoff'] and self.begin<row['cutoff']:
                raise ValueError('history_date_before_retention_boundary')
        db.sql('''CREATE TABLE IF NOT EXISTS '''+self.table+'''(
            id INTEGER PRIMARY KEY CHECK(id=1),run_id TEXT NOT NULL,from_ns BIGINT NOT NULL,
            next_ns BIGINT NOT NULL,end_ns BIGINT NOT NULL,stream_key TEXT NOT NULL,keys_fingerprint TEXT NOT NULL,
            skipped_windows BIGINT NOT NULL DEFAULT 0,published_windows BIGINT NOT NULL DEFAULT 0,
            status TEXT NOT NULL,started_ns BIGINT NOT NULL,updated_ns BIGINT NOT NULL,
            ad_prepared INTEGER NOT NULL DEFAULT 0,ad_started INTEGER NOT NULL DEFAULT 0)''')
        old=self.state()
        if old:
            if (old['from_ns']!=self.begin or old['stream_key']!=state['stream_key']
                    or old['keys_fingerprint']!=state['keys_fingerprint']):
                raise ValueError('different_history_replay_already_recorded')
        else:
            now=clock.time_ns()
            db.sql('INSERT INTO '+self.table+'(id,run_id,from_ns,next_ns,end_ns,stream_key,keys_fingerprint,status,started_ns,updated_ns) '
                'VALUES(1,?,?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,self.begin,self.begin,state['next_ns'],state['stream_key'],state['keys_fingerprint'],'RUNNING',now,now))
        db.conn.commit();return self.state()

    @property
    def table(self):return TABLE.replace('public.','') if self.db.sqlite else TABLE
    def state(self):return self.db.one('SELECT * FROM '+self.table+' WHERE id=1')
    def guard(self,row):
        state=self.db.one('SELECT * FROM viewer_live_state WHERE id=1')
        if (state['stream_key']!=row['stream_key'] or state['keys_fingerprint']!=row['keys_fingerprint']
                or state['next_ns']<row['end_ns']):raise ValueError('history_stream_or_high_watermark_changed')

    def advance(self,row,end,*,skipped=0,published=0):
        status='COMPLETE' if end==row['end_ns'] else 'RUNNING'
        result=self.db.sql('UPDATE '+self.table+' SET next_ns=?,skipped_windows=skipped_windows+?, '
            'published_windows=published_windows+?,status=?,updated_ns=? WHERE id=1 AND run_id=? AND next_ns=?',
            (end,skipped,published,status,clock.time_ns(),row['run_id'],row['next_ns']))
        if result.rowcount!=1:raise ValueError('history_replay_checkpoint_changed')

    def step(self,capture,*,fault=None):
        db=self.db;row=self.state();self.guard(row)
        start=row['next_ns'];end=row['end_ns']
        if start>=end:
            if row['status']!='COMPLETE':self.advance(row,end);db.conn.commit()
            else:db.conn.rollback()
            return {'status':'HISTORY_REPLAY_COMPLETE',**self.summary()}
        stop=min(end,start+512*FIVE_NS)
        valid=db.all('''SELECT w.start_ns FROM viewer_live_windows w JOIN viewer_files f ON f.file_hash=w.file_hash
            WHERE w.start_ns>=? AND w.start_ns<? AND w.end_ns=w.start_ns+?
              AND f.record_count=w.records AND EXISTS(SELECT 1 FROM viewer_live_receipts r
              WHERE r.start_ns=w.start_ns AND r.end_ns=w.end_ns AND r.file_hash=w.file_hash
              AND r.generation=w.generation AND r.records=w.records) ORDER BY w.start_ns''',(start,stop,FIVE_NS))
        known={r['start_ns'] for r in valid};next_ns=start
        while next_ns<stop and next_ns in known:next_ns+=FIVE_NS
        if next_ns>start:
            count=(next_ns-start)//FIVE_NS
            try:
                self.advance(row,next_ns,skipped=count)
                if fault:fault('before_skip_commit')
                db.conn.commit()
            except BaseException:
                db.conn.rollback();raise
            return {'status':'HISTORY_WINDOWS_SKIPPED','skipped':count,**self.summary()}
        db.conn.rollback()
        db.progress('history_capture',window_start_utc=iso(start),window_end_utc=iso(start+FIVE_NS))
        began=clock.monotonic();path=capture(start,start+FIVE_NS);seconds=clock.monotonic()-began
        def checkpoint(stage):
            if stage=='before_commit':self.advance(row,start+FIVE_NS,published=1)
            if fault:fault(stage)
        result=publish_capture(db,path,start,start+FIVE_NS,mode='manual_recheck',capture_seconds=seconds,fault=checkpoint)
        return {'status':'HISTORY_WINDOW_PUBLISHED','publication':result,**self.summary()}

    def summary(self):
        row=self.state()
        return {'run_id':row['run_id'],'from_utc':iso(row['from_ns']),'next_utc':iso(row['next_ns']),
            'target_utc':iso(row['end_ns']),'remaining_windows':(row['end_ns']-row['next_ns'])//FIVE_NS,
            'skipped_complete_windows':row['skipped_windows'],'published_missing_windows':row['published_windows'],
            'replay_status':row['status'],'main_checkpoint_rewound':False}

    def mark_ad(self,name):
        if name not in ('ad_prepared','ad_started'):raise ValueError('invalid_history_handoff_flag')
        self.db.sql('UPDATE '+self.table+' SET '+name+'=1 WHERE id=1');self.db.conn.commit()


def invoke_ad(root,arguments):
    import json,subprocess,sys
    result=subprocess.run([sys.executable,'-B',str(root/'AnomalyDetection/run_anomaly.py'),*arguments],
        cwd=root,text=True,capture_output=True,timeout=40)
    try:value=json.loads(result.stdout)
    except (ValueError,TypeError):raise RuntimeError('ad_history_command_invalid_output') from None
    if result.returncode:raise RuntimeError('ad_history_command_failed:'+str(value.get('status','ERROR')))
    return value


def pending_day(db):
    present=db.one("SELECT to_regclass('public.viewer_history_replay_state') AS present")
    if not present or not present['present']:return None
    row=db.one('SELECT * FROM '+TABLE+' WHERE id=1')
    if row and (row['status']!='COMPLETE' or not row['ad_started']):
        return datetime.fromtimestamp(row['from_ns']/1e9,ZoneInfo('Asia/Tehran')).date().isoformat()
    return None


def handoff(replay,root,*,invoke=invoke_ad):
    row=replay.state();replay.db.conn.commit()
    if row['status']!='COMPLETE':raise ValueError('history_not_complete_for_ad_handoff')
    if not row['ad_prepared']:
        result=invoke(root,['history-rescan','--from-tehran-date',replay.day,'--replay-id',row['run_id']])
        if result.get('status') not in ('HISTORY_RESCAN_PREPARED','HISTORY_RESCAN_ALREADY_PREPARED'):
            raise RuntimeError('ad_history_rescan_not_prepared')
        replay.mark_ad('ad_prepared')
    result=invoke(root,['worker-start'])
    if result.get('status') not in ('STARTED','ALREADY_RUNNING'):
        raise RuntimeError('ad_history_restart_not_confirmed')
    replay.mark_ad('ad_started')
    return {'status':'HISTORY_REPLAY_HANDOFF_COMPLETE','ad_status':result['status'],**replay.summary()}


def run(root,day):
    import json,runpy
    from p24_foundation.viewer_data import ViewerDB,utc_ns
    from p24_foundation.viewer_online import initialize_live,bind_stream,single_worker
    from p24_foundation.viewer_elastic import ElasticREST,ElasticCapture,stream_key
    from p24_foundation.viewer_runtime import ProgressConsole
    from viewer_performance.Run_Viewer_Web import existing_options
    boundary(day)
    cfg=runpy.run_path(str(root/'viewer_config.local.py'));settings=cfg.get('LIVE',{});es=cfg['ELASTICSEARCH']
    directory=Path(settings.get('capture_dir','private/viewer_captures')).expanduser()
    if not directory.is_absolute():directory=root/directory
    capture=ElasticCapture(ElasticREST(es),directory,page_size=settings.get('page_size',5000),
        max_seconds=settings.get('capture_budget_seconds',240))
    console=ProgressConsole();blocked={'history_date_outside_existing_stream','history_date_before_retention_boundary',
        'different_history_replay_already_recorded','history_stream_or_high_watermark_changed',
        'ad_must_be_stopped_during_history_replay','history_replay_checkpoint_changed',
        'live_stream_or_keys_changed','live_keys_changed','viewer_worker_already_running'}
    try:
        while True:
            try:
                with ViewerDB(**existing_options(root)) as db:
                    db.progress_callback=console.progress
                    with single_worker(db,directory/'viewer_worker.lock'):
                        db.init();initialize_live(db)
                        bind_stream(db,start_ns=utc_ns(cfg['LIVE_START_UTC']),stream_key=stream_key(es),
                            overlap_windows=settings.get('overlap_windows',2),lag_seconds=settings.get('lag_seconds',60))
                        replay=HistoryReplay(db,day);row=replay.initialize();db.conn.commit()
                        if row['status']!='COMPLETE':
                            state=invoke_ad(root,['worker-status'])
                            if state.get('process',{}).get('locked') or state.get('web',{}).get('locked'):
                                raise ValueError('ad_must_be_stopped_during_history_replay')
                        console.emit({'status':'HISTORY_REPLAY_RESUMING',**replay.summary()});db.conn.commit()
                        while True:
                            result=replay.step(capture);console.emit(result)
                            if result['status']=='HISTORY_REPLAY_COMPLETE':break
                        console.emit(handoff(replay,root));return
            except KeyboardInterrupt:raise
            except Exception as exc:
                if (isinstance(exc,ValueError) and str(exc) in blocked) or getattr(exc,'sqlstate',None)=='42501':raise
                console.emit({'status':'HISTORY_REPLAY_RETRY','error_type':type(exc).__name__,
                    'sqlstate':getattr(exc,'sqlstate',None),'checkpoint_advanced_on_failure':False})
                clock.sleep(10)
    finally:console.close()
