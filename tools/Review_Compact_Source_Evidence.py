"""Read bounded Elasticsearch evidence for sampled unknown requests; never publish."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
import time
import uuid
from urllib.parse import quote


def choose_samples(review, per_group=6):
    if not 1 <= per_group <= 8:
        raise ValueError('sample_limit_1_to_8')
    selected=[]; seen=set()
    for group in ('UNKNOWN_BEHAVIORS','WAITING','EXPIRED'):
        rows=review.get('groups',{}).get(group,{}).get('samples',[])
        # Diversify paths and dispatcher actions before filling repeated cases.
        first=[]; rest=[]; signatures=set()
        for row in rows:
            sig=json.dumps([sorted(row.get('retained_paths') or []),row.get('dispatch_evidence') or []],sort_keys=True)
            if sig in signatures:rest.append(row)
            else:first.append(row);signatures.add(sig)
        count=0
        for row in first+rest:
            key=row.get('request_id')
            if key in seen:continue
            selected.append(dict(row,review_group=group));seen.add(key);count+=1
            if count==per_group:break
    return selected


def request_query(sample, limit=256):
    from compact_behavior.extract import iso
    if not 1<=limit<=256:raise ValueError('document_limit_1_to_256')
    # UUID validation prevents arbitrary identifiers from broadening this probe.
    canonical=uuid.UUID(sample['request_id']).hex
    variants={canonical,canonical.upper(),str(uuid.UUID(canonical)),str(uuid.UUID(canonical)).upper()}
    for raw in sample.get('source_request_ids') or []:
        if uuid.UUID(raw).hex != canonical:raise ValueError('source_request_identity_mismatch')
        variants.add(raw)
    low=sample.get('first_observed_ns');high=sample.get('last_observed_ns')
    if type(low) is not int or type(high) is not int or not 0<=high-low<=3_600_000_000_000:
        raise ValueError('bounded_request_time_required')
    low-=1_800_000_000_000;high+=1_800_000_000_000
    should=[{'terms':{'RequestID.keyword':sorted(variants)}},{'terms':{'RequestID':sorted(variants)}}]
    # Text-only mappings tokenize UUIDs; phrase lookup plus client identity
    # validation covers them without requiring field-caps or mapping changes.
    should.extend({'match_phrase':{'RequestID':value}} for value in sorted(variants))
    return dict(size=limit,track_total_hits=True,timeout='5s',
        _source=['@timestamp','CallPath','RequestID','message','ExecutionTime'],
        sort=[{'@timestamp':'asc'}],query={'bool':{'filter':[
            {'range':{'@timestamp':{'gte':iso(low),'lte':iso(high)}}},
            {'bool':{'should':should,'minimum_should_match':1}}]}})


def document_summary(hit):
    from compact_behavior.extract import field,LINE,STATUS,facts,sql_fields
    path,status=field(hit,'CallPath');message,_=field(hit,'message')
    path=LINE.sub('',path) if isinstance(path,str) else ''
    message=message if isinstance(message,str) else ''
    if len(path)>256:path=path[:256]+' [truncated]'
    state=facts(hit)  # Same parsing rules as the product, no database calls.
    # No retained payloads or request context are exported, even when parsed.
    surfaces=[]
    for direction in ('inputs','outputs'):
        for value in (state or {}).get(direction,[]):
            payload=value.get('value')
            surfaces.append(dict(direction=direction,path=value['path'],basis=value['basis'],
                top_level_keys=sorted(str(k)[:100] for k in payload)[:64] if isinstance(payload,dict) else [],
                representation=value.get('representation')))
    dispatch=[]
    if path.endswith(('.ud_prc_userSessionHasAccess','.ud_prc_invoiceRequest')):
        params,errors=sql_fields(message)
        for name in ('action','serviceid'):
            value=params.get(name)
            if name not in errors and isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_./-]{1,128}',value):
                dispatch.append(dict(field=name,value=value))
    code=STATUS.search(message)
    return dict(timestamp=field(hit,'@timestamp')[0],call_path=path,path_field_status=status,
        http_completion=bool(re.match(r'^(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+https?://',message)),
        logged_result_code=code[1] if code else None,
        has_input_marker='Input:' in message,has_output_marker='Output:' in message,
        current_extractor_apis=(state or {}).get('apis',[]),dispatch=dispatch,
        extraction_notes=(state or {}).get('issues',[]),surfaces=surfaces)


def inspect_sample(source, sample, limit=256):
    from compact_behavior.extract import field,identity
    body=request_query(sample,limit)
    response=source.request('/'+quote(source.index,safe='*,_-:.')+'/_search?allow_partial_search_results=false',body)
    hits,total=source.checked(response)
    if len(hits)>limit:raise ValueError('source_sample_limit_exceeded')
    if len(hits)>total:raise ValueError('source_count_exceeded')
    documents=[];ids=set();mismatches=0;duplicates=0
    for hit in hits:
        docid=(hit.get('_index'),hit.get('_id'))
        if any(not isinstance(k,str) or not k for k in docid):raise ValueError('source_identity_missing')
        if docid in ids:duplicates+=1;continue
        ids.add(docid)
        raw,status=field(hit,'RequestID')
        if status!='present' or identity(raw)!=uuid.UUID(sample['request_id']).hex:
            mismatches+=1;continue
        documents.append(document_summary(hit))
    complete=total==len(hits) and not mismatches and not duplicates
    return dict(review_group=sample['review_group'],request_id=sample['request_id'],
        query_range=body['query']['bool']['filter'][0]['range']['@timestamp'],
        coverage='COMPLETE_WITHIN_QUERY_RANGE' if complete else 'PARTIAL_WITHIN_QUERY_RANGE',
        matched_source_documents=total,returned_documents=len(hits),identity_mismatches=mismatches,
        duplicate_documents=duplicates,
        call_path_counts=dict(Counter(d['call_path'] for d in documents)),
        recognized_apis=sorted({a for d in documents for a in d['current_extractor_apis']}),documents=documents)


def collect(config, review, *, source_factory=None, per_group=6):
    from compact_behavior.source import ElasticWindow
    source=(source_factory or ElasticWindow)(config,0,1,budget=120)
    expected=review.get('counters',{}).get('stream_id')
    if expected and source.namespace!=expected:
        raise ValueError('review_source_namespace_mismatch')
    source.deadline=time.monotonic()+120
    results=[]
    for sample in choose_samples(review,per_group):
        try:results.append(inspect_sample(source,sample))
        except Exception as exc:
            # Exception strings can contain URLs, query bodies or credentials.
            results.append(dict(review_group=sample['review_group'],request_id=sample.get('request_id'),
                coverage='QUERY_FAILED',failure_type=type(exc).__name__,http_status=getattr(exc,'code',None)))
    return dict(status='READ_ONLY_SOURCE_EVIDENCE',samples=results,
        source_contacted=True,database_modified=False,workers_restarted=False,
        raw_logs_saved=False,payload_values_exported=False,
        limitations=['Selected cases are not a population estimate.',
            'Search is bounded to 30 minutes before and after the sampled evidence; absence is not proof that a log never existed.',
            'At most 256 hits per request; partial, failed and zero-result lookups are explicit.',
            'Original messages, payload values, Session, IP and UserAgent are not exported.',
            'This report does not reclassify or republish stored requests.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project','code-root','review'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();sys.path.insert(0,str(args.code_root.resolve()))
    from compact_behavior.source import settings
    from compact_product.version import verify
    review=json.loads(args.review.read_text(encoding='utf-8-sig'))
    if review.get('status')!='READ_ONLY_UNKNOWN_REVIEW':raise ValueError('unknown_review_required')
    package=verify(args.code_root)
    report=collect(settings(args.project/'viewer_config.local.py')['ELASTICSEARCH'],review)
    report['package']=package;report['input_review']=args.review.name
    output=args.project/'AnomalyDetection/reports'/('Compact_Source_Evidence_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    failed=sum(r['coverage']=='QUERY_FAILED' for r in report['samples'])
    partial=sum(r['coverage']=='PARTIAL_WITHIN_QUERY_RANGE' for r in report['samples'])
    empty=sum(r.get('matched_source_documents')==0 for r in report['samples'])
    print(json.dumps(dict(status=report['status'],output=str(output),sampled_requests=len(report['samples']),
        failed_queries=failed,partial_queries=partial,zero_result_queries=empty,
        database_modified=False,workers_restarted=False)),flush=True)
    return 2 if failed else 0


if __name__=='__main__':raise SystemExit(main())
