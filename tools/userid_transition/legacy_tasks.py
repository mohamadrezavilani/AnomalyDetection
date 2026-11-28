"""Match exact installed Task Scheduler actions before a presentation switch."""
import argparse
import json
import ntpath
from pathlib import Path
from subprocess import list2cmdline


def same_path(a, b):
    return isinstance(a,str) and ntpath.normcase(ntpath.normpath(a)) == ntpath.normcase(ntpath.normpath(b))


def installed(project, python, tasks):
    result = {}
    for kind in ("core", "history"):
        task = tasks.get(kind)
        if task is None and kind == "history":
            continue
        if not task or len(task.get("actions") or ()) != 1:
            raise ValueError(kind + "_registered_task_required")
        action = task["actions"][0]
        root = action.get("WorkingDirectory")
        if not isinstance(root,str) or not ntpath.isabs(root):
            raise ValueError(kind + "_code_directory_missing")
        if kind == "core":
            expected = ["-X","utf8","-B","-m","compact_product","supervise","--project",project]
            exe = python
        else:
            expected = ["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",
                        ntpath.join(root,"compact_product","History_Compact_Product.ps1"),"-Action","Worker",
                        "-Project",project,"-Python",python]
            exe = "powershell.exe"
        if not same_path(action.get("Execute"),exe) or action.get("Arguments") != list2cmdline(expected):
            raise ValueError(kind + "_task_does_not_match_project")
        result[kind] = root
    return result


if __name__ == "__main__":
    import sys
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tasks",type=Path,required=True)
    p.add_argument("--project",required=True)
    p.add_argument("--guardian",required=True)
    args = p.parse_args()
    roots = installed(args.project,sys.executable,json.loads(args.tasks.read_text(encoding="utf-8-sig")))
    from compact_product.version import verify
    package = verify(roots["core"])
    roots.update(build=package["build_id"],sha=package["source_sha256"])
    roots["guardian_args"] = list2cmdline(["-X","utf8","-B",args.guardian,"--project",args.project,
        "--code-root",roots["core"],"--source-sha",roots["sha"]])
    print(json.dumps(roots))
