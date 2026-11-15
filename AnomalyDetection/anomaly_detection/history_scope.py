"""The AD analysis boundary is independent of the Viewer's retention."""
from . import FIVE_NS
from .snapshot import require

STATE_KEY = 'analysis_history_floor_v1'
WRITER_LOCK = 0x414450524F445543
INPUT_LOCK = 0x414450494E505554


def load_floor(store):
    value = store.state(STATE_KEY)
    if not value:
        return 0
    start = value.get('start_ns')
    require(type(start) is int and start > 0 and start % FIVE_NS == 0,
            'INVALID_AD_HISTORY_BOUNDARY')
    return start


def effective_floor(source):
    return max(source.get('analysis_floor_ns', 0), source.get('retention_cutoff_ns', 0))


def target_scope(store,field='j.target_ns'):
    """Scheduling predicate with validated internal identifiers and integer."""
    require(field in ('j.target_ns','s.target_ns','target_ns','start_ns'),'INVALID_HISTORY_SCOPE_FIELD')
    floor=getattr(store,'history_floor_ns',0)
    require(type(floor) is int and floor>=0,'INVALID_AD_HISTORY_BOUNDARY')
    return ' AND '+field+'>='+str(floor)+' ' if floor else ' '


def replay_boundary(source,row):
    """Expose only the committed replay prefix as the AD scheduling frontier.

    The forward Viewer checkpoint stays unchanged in its own table and is
    retained explicitly in metadata. A missing historical window is never a
    published empty window, nor a reason to jump to a later retained island.
    """
    if not row:return
    require(row['stream_key']==source['stream_key'] and row['keys_fingerprint']==source['keys_fingerprint'],
            'HISTORY_REPLAY_SOURCE_IDENTITY_MISMATCH')
    require(row['status'] in ('RUNNING','COMPLETE') and
            all(type(row[k]) is int and row[k]>0 and row[k]%FIVE_NS==0 for k in ('from_ns','next_ns','end_ns')) and
            row['from_ns']<=row['next_ns']<=row['end_ns']<=source['next_ns'], 'INVALID_HISTORY_REPLAY_BOUNDARY')
    require(row['status']!='COMPLETE' or row['next_ns']==row['end_ns'],'INVALID_HISTORY_REPLAY_BOUNDARY')
    source['viewer_forward_next_ns']=source['next_ns']
    source['history_replay']={k:row[k] for k in ('run_id','status','from_ns','next_ns','end_ns')}
    if row['status']=='RUNNING':
        source['next_ns']=row['next_ns']
        source['analysis_floor_ns']=max(source.get('analysis_floor_ns',0),row['from_ns'])
        source['analysis_frontier']='COMMITTED_REPLAY_PREFIX'
