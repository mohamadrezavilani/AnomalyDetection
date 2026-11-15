"""Finish bounded page groups without starving other source work.

Publication/generation fences are unchanged. At most three continuation turns
follow a regular source turn; regular source/audit lanes keep advancing.
"""
def reduce_failed_page(source,phase,lane):
    """A stale active lane must never throttle an unrelated evidence read."""
    phases={'fresh_cursor':'read_fresh_window','learning_cursor':'read_learning_window',
            'semantic_keyset':'read_semantic_keyset'}
    valid=(phase==phases.get(lane) or lane in ('fresh_cursor','learning_cursor','older_learning_cursor','overlap_cursor')
           and phase=='read_'+lane)
    if not valid:return False
    if callable(getattr(source,'reduce_page_size',None)):source.reduce_page_size(lane)
    else:source.page_size=max(64,source.page_size//2)
    return True


class WindowContinuations:
    def __init__(self):self.pending=None;self.streak=0

    def take(self):
        if self.pending is not None and self.streak<3:
            self.streak+=1;return self.pending
        self.streak=0
        return None

    def notice(self,lane,result):
        if result.get('status') in ('READING','RESTART_SNAPSHOT'):
            self.pending=lane
        elif self.pending==lane:
            self.pending=None

    def ready(self):return self.pending is not None and self.streak<3
