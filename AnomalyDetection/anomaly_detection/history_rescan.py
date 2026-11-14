"""Non-destructive history rescan: retain facts, models, cases and feedback."""
from contextlib import ExitStack
from pathlib import Path
import uuid
from .history_scope import WRITER_LOCK,STATE_KEY
from .history_reset import tehran_boundary
from .process_control import OwnedProcessLock
from .snapshot import require

REQUEST='history_rescan_request_v1'
CURSORS=('fresh_cursor','learning_cursor','older_learning_cursor','service_sample_fresh_cursor',
    'service_sample_old_cursor','scenario_traffic_cursor','scenario_old_traffic_cursor')


def prepare(store,day,replay_id):
    _,start=tehran_boundary(day)
    require(isinstance(replay_id,str) and len(replay_id)==32 and uuid.UUID(replay_id).hex==replay_id,'INVALID_HISTORY_REPLAY_ID')
    existing=store.state(REQUEST)
    if existing and existing.get('replay_id')==replay_id:
        require(existing.get('start_ns')==start,'HISTORY_RESCAN_ID_DATE_MISMATCH')
        return {'status':'HISTORY_RESCAN_ALREADY_PREPARED','replay_id':replay_id,'start_ns':start,'data_deleted':False}
    with store.transaction():
        for key in (WRITER_LOCK,):
            require(store.raw.execute('SELECT pg_try_advisory_xact_lock(%s) AS locked',(key,)).fetchone()['locked'],'AD_WRITER_MUST_BE_STOPPED')
        binding=store.state('source_binding')
        require(bool(binding),'AD_SOURCE_BINDING_NOT_INITIALIZED')
        old_floor=store.state(STATE_KEY)
        # Only scheduling state changes. All canonical/human tables survive.
        for name in CURSORS:store.save_state(name,{'next_ns':start})
        semantic=store.state('semantic_cursor')
        store.save_state('semantic_cursor',{'after':None,'completed_passes':semantic.get('completed_passes',0)})
        store.save_state('overlap_cursor',{})
        store.save_state(STATE_KEY,{'start_ns':start,'start_tehran':day,'rescan_id':replay_id})
        store.save_state(REQUEST,{'replay_id':replay_id,'start_ns':start,'day':day,'previous_floor':old_floor})
        store._history_floor_ns=None
    return {'status':'HISTORY_RESCAN_PREPARED','replay_id':replay_id,'start_ns':start,'data_deleted':False,
        'models_preserved':True,'feedback_preserved':True}


def run(root,sha,day,replay_id):
    from .native_pg import database
    from .product_store import ProductStore
    root=Path(root)
    # Read-only idempotence also works after a successful handoff started AD.
    with database(root,readonly=True) as raw:
        saved=ProductStore(raw).state(REQUEST)
        if saved and saved.get('replay_id')==replay_id:
            _,start=tehran_boundary(day)
            require(saved.get('start_ns')==start,'HISTORY_RESCAN_ID_DATE_MISMATCH')
            return {'status':'HISTORY_RESCAN_ALREADY_PREPARED','replay_id':replay_id,'start_ns':start,'data_deleted':False}
    with ExitStack() as stack:
        for resource in ('baseline','actor','web'):
            stack.enter_context(OwnedProcessLock(root,'history_rescan',sha,resource=resource))
        raw=stack.enter_context(database(root))
        return prepare(ProductStore(raw),day,replay_id)
