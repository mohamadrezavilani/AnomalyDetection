"""Bounded read-only comparison of stored and current interpretation by RequestID."""
import argparse
import json
from pathlib import Path
from datetime import datetime
from compact_behavior.extract import behavior_id, materialize
from compact_behavior.store import Store
from compact_product.config import load
from compact_product.version import verify


def inspect(db,cfg,stream,requests):
    if not 1<=len(requests)<=10:raise ValueError('one_to_ten_requests_required')
    values=[]
    for request in requests:
        row=db.conn.execute(f'''SELECT b.behavior_id,b.api,b.result_code,b.observed_at_ns,
            b.features->>'service_key' AS stored_service,b.features->>'service_binding' AS stored_binding,p.state
            FROM {cfg.source_schema}.behaviors b JOIN {cfg.source_schema}.behavior_payloads p USING(behavior_id)
            WHERE b.stream_id=%s AND b.behavior_id=%s''',(stream,behavior_id(stream,request))).fetchone()
        if not row:
            values.append(dict(request_id=request,found=False));continue
        body=materialize(stream,row.pop('state'))
        values.append(dict(row,request_id=request,found=True,current_service=body['service_key'],
            current_binding=body['service_binding'],current_role=body['operation_role'],current_quality=body['quality']))
    return dict(status='READ_ONLY_COMPACT_REQUEST_REVIEW',requests=values,database_modified=False,source_contacted=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--request-id',action='append',required=True)
    args=p.parse_args();verify()
    cfg,settings,stream=load(args.project)
    db=Store(settings['DATABASE'],schema=cfg.source_schema,application='request-review')
    try:
        db.conn.execute('SET default_transaction_read_only=on')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            db.conn.execute("SET LOCAL statement_timeout='10s'")
            report=inspect(db,cfg,stream,args.request_id)
        folder=args.project/'AnomalyDetection'/'reports';folder.mkdir(parents=True,exist_ok=True)
        output=folder/('Compact_Request_Review_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'.json')
        output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(dict(status=report['status'],output=str(output),requests=report['requests'],database_modified=False),ensure_ascii=False),flush=True)
    finally:db.close()


if __name__=='__main__':raise SystemExit(main())
