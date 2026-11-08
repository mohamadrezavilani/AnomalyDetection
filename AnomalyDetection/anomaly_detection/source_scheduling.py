"""Finish bounded page groups without starving other source work.

Publication/generation fences are unchanged. At most three continuation turns
follow a regular source turn; regular source/audit lanes keep advancing.
"""
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
