"""Windows scheduled task. Supervise only the existing web and analysis processes."""
import argparse
import sys
import time
from pathlib import Path


def supervise(project, pinned_root, expected_sha):
    # This standalone file is installed next to the preserved project's local control files.
    # Import the exact deployed application even if the new release worktree moves.
    sys.path.insert(0, str(pinned_root))
    from compact_behavior.__main__ import save
    from compact_product.version import verify
    from compact_product.runtime import start, status
    from compact_product.config import load
    from compact_behavior.store import Store
    import hashlib
    if verify()["source_sha256"] != expected_sha:
        raise ValueError("archived_application_build_changed")
    cfg, settings, stream = load(project)
    guard = "p24_presentation_" + hashlib.sha256(stream.encode()).hexdigest()[:14]
    store = Store(settings["DATABASE"],schema=cfg.source_schema,application="presentation.guardian")
    try:
        found = store.conn.execute("""SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(%s)
            AND tgname=%s AND tgenabled='A' AND NOT tgisinternal""",(cfg.source_schema+".windows",guard)).fetchone()
        if not found:
            raise ValueError("archive_guard_not_enabled")
    finally:
        store.close()
    while True:
        active = status(project)
        for role in ("web", "analysis"):
            if active[role]["running"] and active[role].get("package",{}).get("source_sha256") != expected_sha:
                raise ValueError("unexpected_preserved_role_build")
            if not active[role]["running"]:
                start(project, roles=(role,))
        ready = all(active[r]["running"] and active[r].get("package",{}).get("source_sha256") == expected_sha
                    for r in ("web","analysis"))
        if ready:
            save(project / "compact_runtime/presentation/guardian.local.json",
                 dict(source_sha=expected_sha,checked_unix_s=int(time.time()),web=True,analysis=True))
        time.sleep(30 if ready else 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project",required=True,type=Path)
    parser.add_argument("--code-root",required=True,type=Path)
    parser.add_argument("--source-sha",required=True)
    a = parser.parse_args()
    supervise(a.project.resolve(), a.code_root.resolve(), a.source_sha)
