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
