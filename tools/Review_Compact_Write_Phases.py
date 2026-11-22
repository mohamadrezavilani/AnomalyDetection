"""Read bounded local log tails; export timings only, without DB/source access."""
import argparse
import json
from pathlib import Path
import time

PHASES = ('stream_lock_acquire_seconds', 'existing_lookup_seconds', 'key_preparation_seconds',
    'tombstone_lookup_seconds', 'stage_copy_seconds', 'context_upsert_seconds', 'behavior_upsert_seconds',
    'payload_upsert_seconds', 'pending_upsert_seconds', 'pending_expiry_seconds',
    'pending_retention_seconds', 'dirty_marking_seconds', 'publication_bookkeeping_seconds')
FIELDS = ('start_ns', 'end_ns', 'fresh_publication', 'source_records', 'requests', 'total_seconds',
    'read_extract_seconds', 'read_existing_seconds', 'merge_features_seconds', 'write_seconds',
    'commit_seconds', 'database_seconds') + PHASES


def sample(path, role, budget=512*1024):
    try:
        with path.open('rb') as file:
            size=file.seek(0,2);offset=max(0,size-budget);file.seek(offset)
            raw=file.read(budget)
    except FileNotFoundError:
        return dict(role=role,status='LOG_NOT_PRESENT',rows=[])
    lines=raw.splitlines()
    if offset and lines:lines=lines[1:]  # possibly a partial first record
    rows=[]
    for line in lines:
        try:value=json.loads(line)
        except (ValueError,UnicodeError):continue
        if not isinstance(value,dict) or value.get('event') not in ('PUBLICATION','HISTORY_PUBLICATION'):
            continue
        if not value.get('fresh_publication') or not any(k in value for k in PHASES):
            continue
        rows.append({k:value[k] for k in FIELDS if k in value})
    rows=rows[-20:]
    return dict(role=role,status='PHASE_SAMPLES_AVAILABLE' if rows else 'NO_DETAILED_FRESH_SAMPLES_IN_TAIL',
                bytes_read=len(raw),tail_only=True,rows=rows)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    args=parser.parse_args();project=args.project.resolve()
    values=[sample(project/'compact_runtime'/name,role) for name,role in
            [('ingest.log','ingest'),('history.log','history')]]
    output=project/'AnomalyDetection/reports'/('Compact_Write_Phases_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    result=dict(status='READ_ONLY_WRITE_PHASE_REVIEW',database_modified=False,workers_restarted=False,
                aggregate_and_subphase_timers_overlap_do_not_sum=True,roles=values)
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],output=str(output),
        samples={v['role']:len(v['rows']) for v in values},database_modified=False,workers_restarted=False)),flush=True)


if __name__=='__main__':main()
