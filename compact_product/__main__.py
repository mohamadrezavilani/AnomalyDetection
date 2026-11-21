"""Compact product control. Server cutover is explicit, reversible and receipted."""

import argparse
import json
from pathlib import Path
import sys
from .config import load
from .runtime import ROLES, status, start, stop, worker


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "action",
        choices=(
            "worker",
            "start",
            "stop",
            "status",
            "health",
            "version",
            "trial",
            "install",
            "rollback",
            "observe",
            "supervise",
        ),
    )
    p.add_argument("role", nargs="?", choices=ROLES)
    p.add_argument("--project", type=Path, default=Path.cwd())
    p.add_argument("--token")
    p.add_argument("--legacy-receipt", type=Path)
    p.add_argument("--receipt", type=Path)
    p.add_argument("--seconds", type=int, default=600)
    a = p.parse_args(argv)
    project = a.project.resolve()
    try:
        if a.action == "supervise":
            from .runtime import supervise

            return supervise(project, a.token or __import__("uuid").uuid4().hex)
        if a.action == "worker":
            if not a.role or not a.token:
                p.error("worker requires role and token")
            return worker(project, a.role, a.token)
        if a.action == "version":
            from .version import verify

            result = verify()
        elif a.action in ("trial", "install", "rollback", "observe"):
            from .operations import execute

            result = execute(project, a)
        elif a.action == "status":
            result = status(project)
        elif a.action in ("start", "stop"):
            result = (start if a.action == "start" else stop)(
                project, roles=(a.role,) if a.role else ROLES
            )
        else:
            from .health import health
            from compact_ad.store import AnalysisStore

            cfg, source, stream = load(project)
            db = AnalysisStore(
                source["DATABASE"], schema=cfg.source_schema, ad_schema=cfg.ad_schema
            )
            try:
                result = health(db.conn, cfg, stream)
            finally:
                db.close()
        print(json.dumps(result, ensure_ascii=True, default=str), flush=True)
        return (
            0
            if result.get("status")
            not in (
                "COMPACT_TRIAL_INCOMPLETE",
                "COMPACT_INSTALL_ROLLED_BACK",
                "COMPACT_RESTORE_INCOMPLETE",
                "COMPACT_OBSERVATION_INVALID",
            )
            else 2
        )
    except Exception as exc:
        print(
            json.dumps(
                dict(
                    status="COMPACT_CONTROL_FAILED",
                    failure=dict(
                        type=type(exc).__name__,
                        code=(
                            str(exc)
                            if isinstance(exc, (ValueError, TimeoutError))
                            else None
                        ),
                        sqlstate=getattr(exc, "sqlstate", None),
                    ),
                ),
                ensure_ascii=True,
            ),
            flush=True,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
