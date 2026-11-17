"""Count returned raw bodies without retaining payloads or query values."""
from functools import wraps

from viewer_performance.capacity.trace import Trace,Connection,Cursor


class BodyCursor(Cursor):
    def received(self,value,rows):
        columns=self.raw.description or ()
        if any(getattr(c,'name',c[0])=='payload' for c in columns):self.trace.raw_body_rows+=rows
        return value

    def fetchone(self):
        value=super().fetchone();return self.received(value,int(value is not None))

    def fetchmany(self,*args,**kwargs):
        value=super().fetchmany(*args,**kwargs);return self.received(value,len(value))

    def fetchall(self):
        value=super().fetchall();return self.received(value,len(value))

    def __iter__(self):
        for value in super().__iter__():yield self.received(value,1)


class BodyConnection(Connection):
    def execute(self,statement,*args,**kwargs):
        with self.trace.span('driver:execute',statement):value=self.raw.execute(statement,*args,**kwargs)
        return BodyCursor(value,self.trace)

    def cursor(self,*args,**kwargs):return BodyCursor(self.raw.cursor(*args,**kwargs),self.trace)


class ScopeTrace(Trace):
    def __init__(self):super().__init__();self.raw_body_rows=0

    def attach(self,db):
        super().attach(db);db.conn=BodyConnection(self.original_conn,self)
        for name in ('_rebuild_requests','_reconcile_payment_outcomes','_reconcile_business_outcomes','build_semantic_index'):
            original=getattr(db,name);self.originals[name]=(name in db.__dict__,original)
            def wrapped(method,label):
                @wraps(method)
                def call(*args,**kwargs):
                    with self.span('method:'+label):return method(*args,**kwargs)
                return call
            setattr(db,name,wrapped(original,name))
        return self

    def report(self):
        return super().report()|dict(raw_body_rows_fetched=self.raw_body_rows,
            raw_body_scope='Rows returned by this connection with the payload column; not distinct versions or physical disk reads.')
