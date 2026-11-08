"""Bounded web failures and local GET evidence; no payload, SQL or cookie export."""
import json,time,traceback,uuid,threading,re
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from . import BUILD_ID
from .process_control import read_json,write_json,safe_failure
LOCK=threading.Lock()


def record(root,path,stage,exc,queries):
    key=uuid.uuid4().hex[:12]
    route=path if path in ('/','/incidents','/scenarios','/coverage','/evaluations') else '/detail'
    event={'id':key,'build_id':BUILD_ID,'at_ns':time.time_ns(),'route':route,'phase':stage,
        'failure':safe_failure(exc),'queries':queries[-16:],
        'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(exc.__traceback__)[-6:]]}
    try:
        target=Path(root)/'reports/web_diagnostics.json'
        with LOCK:
            old=read_json(target,{}).get('events',[])
            write_json(target,{'build_id':BUILD_ID,'events':(old+[event])[-20:],'private_payloads_included':False})
    except Exception:pass
    return key


def probe(*,opener=None,clock=None,include_details=False):
    opener=opener or urlopen;clock=clock or time.monotonic;deadline=clock()+(20 if include_details else 15);pages=[]
    paths=['/incidents','/incidents?view=actors','/incidents?view=cases','/api/status']
    if include_details:paths+=['/','/coverage','/incidents?view=cases&bucket=ALL']
    detail_added=False
    for path in paths:
        began=clock();item={'path':path,'method':'GET','models_executed':False}
        if began>=deadline:item['status']='DEFERRED_BUDGET';pages.append(item);continue
        try:
            request=Request('http://127.0.0.1:5022'+path,headers={'Host':'127.0.0.1:5022'})
            with opener(request,timeout=min(5,max(.05,deadline-began))) as response:
                body=response.read(2*1024*1024+1);item['http_status']=response.status
            if len(body)>2*1024*1024:item['status']='BODY_LIMIT'
            else:
                value=body.decode('utf-8',errors='replace')
                if path=='/api/status':item['build_matches']=json.loads(value).get('build_id')==BUILD_ID
                else:
                    item['build_matches']=BUILD_ID in value;item['rtl']='dir="rtl"' in value
                    item['table_present']='<table' in value
                    if include_details and not detail_added:
                        match=re.search(r'href="/case/(ac1:[0-9a-f]{64})(?:["?])',value)
                        if match:paths.append('/case/'+match[1]);detail_added=True
                    if path.startswith('/case/'):
                        item['noc_dossier_present']='محتوا، قبض‌ها و IPهای همین پرونده' in value
                        item['method_reason_present']='چرا فعال شده و چقدر قابل اتکاست' in value
                        item['evidence_read_status']='PENDING_BUDGET' if 'جزئیات در زمان این خواندن آماده نشد' in value else 'HTML_PRESENT' if item['noc_dossier_present'] else 'NOT_PRESENT'
                item['status']='PASS_GET_RENDER' if item['http_status']==200 and item['build_matches'] else 'WRONG_BUILD_OR_STATUS'
        except HTTPError as exc:item.update(status='HTTP_ERROR',http_status=exc.code);exc.close()
        except Exception as exc:item.update(status='READ_FAILED',failure={'error_type':type(exc).__name__})
        item['elapsed_seconds']=round(max(0,clock()-began),6);pages.append(item)
    return {'status':'PASS_LOCAL_GETS' if all(p['status']=='PASS_GET_RENDER' for p in pages) else 'PARTIAL_OR_FAILED_LOCAL_GETS',
        'build_id':BUILD_ID,'pages':pages,'source_reads':0,'database_modified':False,'models_executed':False,
        'detail_probe':'CASE_LINK_FOUND' if detail_added else 'NO_VISIBLE_CASE_LINK' if include_details else 'NOT_REQUESTED',
        'proves_detection_accuracy':False,'html_payloads_or_cookies_exported':False}
