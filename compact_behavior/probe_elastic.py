"""Read only one ES search page; no PostgreSQL or process-control imports."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import time
import uuid
import zipfile
from . import FIVE
from .extract import instant,iso
from .source import ElasticWindow,settings


def probe(config,start,*,source_factory=ElasticWindow):
    result=dict(start_utc=iso(start),end_utc=iso(start+FIVE),database_modified=False,
                settings_modified=False,services_stopped=False,first_page_only=True,
                full_window_completeness='NOT_TESTED',response_diagnostics=[])
    source=source_factory(config,start,start+FIVE,page_size=1,budget=45)
    source.deadline=time.monotonic()+10
    try:
        info=source.request('/',method='GET')
        version=info.get('version',{}) if isinstance(info,dict) else {}
        result['elasticsearch_version']={k:version.get(k) for k in ['number','build_flavor','build_type']}
    except Exception as exc:result['version_read']={'type':type(exc).__name__,'http_status':getattr(exc,'code',None)}
    iterator=source.records();began=time.monotonic()
    try:
        value=next(iterator,None)
        result.update(status='FIRST_SEARCH_PAGE_VALID',first_hit_present=value is not None)
        del value
    except Exception as exc:
        result.update(status='FIRST_SEARCH_PAGE_REJECTED',failure=dict(type=type(exc).__name__,
            code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None,
            http_status=getattr(exc,'code',None),details=getattr(exc,'details',None)))
    finally:
        iterator.close();result['elapsed_seconds']=time.monotonic()-began
        result['response_diagnostics']=source.response_diagnostics
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,required=True);p.add_argument('--start')
    a=p.parse_args();project=a.project.resolve()
    start=instant(a.start) if a.start else (time.time_ns()-60_000_000_000)//FIVE*FIVE-3*FIVE
    if start%FIVE:p.error('aligned five-minute start required')
    report=dict(status='READ_ONLY_ES_PROBE_EXPORTED',database_modified=False,services_stopped=False)
    try:
        from .version import verify
        report['package']=verify()
        cfg=settings(project/'viewer_config.local.py');report['probe']=probe(cfg['ELASTICSEARCH'],start)
    except Exception as exc:report['failure']={'type':type(exc).__name__,'code':str(exc) if isinstance(exc,ValueError) else None}
    folder=project/'AnomalyDetection/reports';folder.mkdir(parents=True,exist_ok=True)
    path=folder/('Compact_ES_Probe_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.zip')
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:archive.writestr('probe.json',json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps({'status':report['status'],'output':str(path),'database_modified':False,'services_stopped':False}),flush=True)


if __name__=='__main__':main()
