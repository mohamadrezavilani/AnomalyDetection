"""SET LOCAL survives RELEASE SAVEPOINT: restore the enclosing budget explicitly."""
from contextlib import contextmanager


@contextmanager
def statement_budget(raw,milliseconds):
    previous=raw.execute("SELECT current_setting('statement_timeout') AS value").fetchone()['value']
    try:
        with raw.transaction():
            raw.execute("SELECT set_config('statement_timeout',%s,true)",(str(int(milliseconds))+'ms',))
            yield
    finally:
        raw.execute("SELECT set_config('statement_timeout',%s,true)",(previous,))
