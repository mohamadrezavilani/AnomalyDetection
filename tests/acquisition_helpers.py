"""Entirely synthetic capture builders; no private logs or scroll cursors."""
import copy
import json

from p24_foundation.intake import decode_batch
from tests.helpers import document

START = "2026-10-20T07:25:00Z"
END = "2026-10-20T07:30:00Z"


def capture(rows=None, *, terminal=True, relation="eq"):
    if rows is None:
        rows = [document(rid="capture-A", oid="capture-origin-A"),
                document(rid="capture-B", oid="capture-origin-B")]
    rows = copy.deepcopy(rows)
    total = dict(value=len(rows), relation=relation) if relation else None
    pages = []
    for position, hits in enumerate(([r] for r in rows)):
        pages.append(dict(ordinal=position,
            request_cursor=None if position == 0 else "SYNTHETIC_CURSOR_"+str(position-1),
            received_at="2026-10-20T07:30:31."+str(position).zfill(6)+"Z",
            response=dict(timed_out=False, _shards=dict(total=1, successful=1, failed=0),
                          _scroll_id="SYNTHETIC_CURSOR_"+str(position), hits=dict(total=total, hits=hits))))
    if terminal:
        position = len(pages)
        pages.append(dict(ordinal=position,
            request_cursor=None if not pages else "SYNTHETIC_CURSOR_"+str(position-1),
            received_at="2026-10-20T07:30:32Z",
            response=dict(timed_out=False, _shards=dict(total=1, successful=1, failed=0),
                          _scroll_id="SYNTHETIC_CURSOR_FINAL", hits=dict(total=total, hits=[]))))
    body = dict(query={"bool": {"filter": [{"range": {"@timestamp": {"gte": START, "lt": END}}}]}},
                sort=["_doc"], size=10000, _source=True)
    return dict(acquisition=dict(version="p24-scroll-capture.1", window_start=START, window_end=END,
        started_at="2026-10-20T07:30:30Z", finished_at="2026-10-20T07:31:00Z",
        index_pattern="fixture-*", expected_slices=1, attempt_budget=3,
        query=dict(scope="window_only", time_field="@timestamp", range_mode="gte_lt", level_filter=[])),
        slices=[dict(id=0, attempts=[dict(number=1, initial_request=dict(index="fixture-*", scroll="10m", body=body), pages=pages)])])


def captured(packet, **kwargs):
    return decode_batch((json.dumps(packet, ensure_ascii=False)+"\n").encode(), **kwargs)


def assessment(packet):
    return captured(packet).coverage["acquisition"]


def attempt(packet):
    return packet["slices"][0]["attempts"][-1]
