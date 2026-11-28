"""Cooperative stop of only the old intake paths after their owned tasks are disabled."""
from pathlib import Path
import time

from account_behavior.storage import connect
from compact_behavior.__main__ import save
from compact_product.config import load
from compact_product.runtime import paths, role_key


def running(db,cfg,stream,role):
    key = role_key(cfg,stream,role)
    row = db.execute(f"""SELECT r.token FROM {cfg.source_schema}.runtime_roles r
      JOIN pg_stat_activity a ON a.pid=r.backend_pid AND a.backend_start=r.backend_start
      JOIN pg_locks l ON l.pid=a.pid AND l.locktype='advisory' AND l.granted AND l.objsubid=1
      WHERE r.role=%s AND l.classid=(%s::bigint>>32)::oid
      AND l.objid=(%s::bigint&4294967295)::oid""",(role,key,key)).fetchone()
    return row["token"] if row else None


def stop_roles(project):
    cfg,settings,stream = load(project)
    with connect(settings["DATABASE"]) as db:
        for roles in (("supervisor",),("history","ingest")):
            requested = set()
            deadline = time.monotonic() + 150
            quiet_since = None
            while time.monotonic() < deadline:
                active = {role:running(db,cfg,stream,role) for role in roles}
                if not any(active.values()):
                    if quiet_since is not None and time.monotonic()-quiet_since >= 2:
                        break
                    quiet_since = quiet_since or time.monotonic()
                else:
                    quiet_since = None
                    for role,token in active.items():
                        if token and (role,token) not in requested:
                            save(paths(project,role)[2],{"token":token})
                            requested.add((role,token))
                time.sleep(.5)
            else:
                raise TimeoutError("presentation_source_roles_still_stopping")
    return True


if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project",type=Path,required=True)
    stop_roles(p.parse_args().project)
    print('{"status":"PRESENTATION_INPUT_ROLES_STOPPED"}')
