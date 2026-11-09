"""Explicit inspect/capture/plan/publish/replay commands for finite operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from p24_foundation.collector_pipeline import (capture_summary, capture_window, load_plan,
                                               publish_plan, verified_target, verified_transport)
from p24_foundation.errors import FoundationError
from p24_foundation.intake import MAX_INPUT_BYTES, MAX_RECORDS, read_batch
from p24_foundation.privacy import canonical
from p24_foundation.time import microsecond_cutoff


def generate_plan(args):
    """Build a validated plan from only the explicitly named local captures."""
    if args.output.exists():
        raise FoundationError("collector_plan_output_exists")
    if not 1 <= len(args.captures) <= 128:
        raise FoundationError("collector_plan_input_limit")
    replacements = []
    if args.replacements is not None:
        try:
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError()
                    result[key] = value
                return result
            with args.replacements.open("rb") as stream:
                raw = stream.read(128_001)
            if len(raw) > 128_000:
                raise ValueError()
            replacements = json.loads(raw, object_pairs_hook=unique,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
            if not isinstance(replacements, list):
                raise ValueError()
        except (OSError, ValueError, TypeError):
            raise FoundationError("invalid_collector_replacements") from None

    hints = {}
    try:
        for item in replacements:
            if not isinstance(item, dict) or set(item) != {"window_start", "window_end", "snapshot_id", "intake_revision"}:
                raise ValueError()
            start = microsecond_cutoff(item["window_start"]).epoch_ns
            end = microsecond_cutoff(item["window_end"]).epoch_ns
            key = (start, end)
            if key in hints:
                raise ValueError()
            hints[key] = {"snapshot_id": item["snapshot_id"], "intake_revision": item["intake_revision"]}
        entries, used = [], set()
        total_bytes = total_rows = total_decoded_bytes = 0
        for capture_path in args.captures:
            path = Path(capture_path).resolve(strict=True)
            batch = read_batch(path)
            total_bytes += len(batch.original)
            total_rows += len(batch.records)
            total_decoded_bytes += len(canonical(batch.records))
            if (total_bytes > MAX_INPUT_BYTES or total_decoded_bytes > MAX_INPUT_BYTES
                    or total_rows > MAX_RECORDS):
                raise FoundationError("collector_plan_input_limit")
            if batch.coverage.get("input_format") != "scroll_capture":
                raise ValueError()
            acquisition = batch.coverage["acquisition"]
            start_text, end_text = acquisition["declared_window_start"], acquisition["declared_window_end"]
            key = (microsecond_cutoff(start_text).epoch_ns, microsecond_cutoff(end_text).epoch_ns)
            entry = {"path": str(path), "sha256": hashlib.sha256(batch.original).hexdigest()}
            if key in hints:
                entry["replaces"] = hints[key]
                used.add(key)
            entries.append(entry)
        if used != set(hints):
            raise ValueError()
        plan = {"version": "p24-collector-import.1", "stream": args.stream,
                "index_pattern": args.index_pattern, "expected_generation": args.expected_generation,
                "event_cutoff": args.event_cutoff, "captures": entries}
        encoded = canonical(plan)
        # Validate all hashes, scopes, windows, and limits using the publisher's loader.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".collector-plan-", dir=args.output.parent)
        temp_path = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
            load_plan(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)
        descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return {"status": "planned", "captures": len(entries), "sha256": hashlib.sha256(encoded).hexdigest(),
                "database_used": False, "network_used": False}
    except FoundationError:
        raise
    except FileExistsError:
        raise FoundationError("collector_plan_output_exists") from None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise FoundationError("invalid_collector_plan_input") from None


def load_transport(root):
    """Load pinned transport and trusted settings without starting its main loop."""
    files = verified_transport(root)
    target = Path(root).resolve()
    config = types.ModuleType("config")
    config.__file__ = str(target / "PopulationVersion/config.py")
    collector = types.ModuleType("p24_verified_collector")
    collector.__file__ = str(target / "elastic_log_fetcher.py")
    prior_config = sys.modules.get("config")
    prior_path = sys.path[:]
    try:
        sys.path[:0] = [str(target / "PopulationVersion"), str(target)]
        sys.modules["config"] = config
        from contextlib import redirect_stdout,redirect_stderr
        with open(os.devnull,"w") as sink,redirect_stdout(sink),redirect_stderr(sink):
            exec(compile(files["PopulationVersion/config.py"], config.__file__, "exec"), config.__dict__)
            exec(compile(files["elastic_log_fetcher.py"], collector.__file__, "exec"), collector.__dict__)
        return collector
    finally:
        sys.path[:] = prior_path
        if prior_config is None:
            sys.modules.pop("config", None)
        else:
            sys.modules["config"] = prior_config



def collect(args):
    if args.output.exists():
        raise FoundationError("collector_capture_output_exists")
    collector=load_transport(args.target_root)
    with collector.fetch_budget(args.max_runtime_seconds):
        batch = capture_window(collector.get_es(), index_pattern=collector.INDEX_PATTERN,
            start=args.start, end=args.end, before_request=collector._remaining_fetch_time,
            max_runtime_seconds=args.max_runtime_seconds, page_size=collector.SCROLL_PAGE_SIZE)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Refuse replacement of any existing capture, including failed attempts.
    descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(batch.original)
        stream.flush()
        os.fsync(stream.fileno())
    result = capture_summary(batch)
    eligible = result["query_traversal_complete"] and result["window_scope_eligible"]
    result.update(status="captured" if eligible else "captured_not_eligible",
                  production_modified=False, background_collector_started=False)
    return result

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Verify target source hashes; no imports or network")
    inspect.add_argument("--target-root", type=Path, required=True)
    transport = commands.add_parser("inspect-transport", help="Verify/load collector and trusted local settings only; no network or legacy writers")
    transport.add_argument("--target-root",type=Path,required=True)
    capture = commands.add_parser("capture", help="Explicitly read one five-minute ES window into a private transcript")
    capture.add_argument("--target-root", type=Path, required=True)
    capture.add_argument("--start", required=True)
    capture.add_argument("--end", required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--max-runtime-seconds", type=int, default=120)
    publish = commands.add_parser("publish", help="Apply one digest-pinned plan to an initialized disposable database")
    publish.add_argument("--config", type=Path, required=True)
    publish.add_argument("--plan", type=Path, required=True)
    plan_command = commands.add_parser("plan", help="Create a validated import plan from explicit private captures")
    plan_command.add_argument("--stream", required=True)
    plan_command.add_argument("--index-pattern", required=True)
    plan_command.add_argument("--expected-generation", type=int, required=True)
    plan_command.add_argument("--event-cutoff", required=True)
    plan_command.add_argument("--captures", type=Path, nargs="+", required=True)
    plan_command.add_argument("--replacements", type=Path)
    plan_command.add_argument("--output", type=Path, required=True)
    replay = commands.add_parser("replay", help="Supervise explicitly ordered publication plans; no retry or resume")
    replay.add_argument("--config", type=Path, required=True)
    replay.add_argument("--plans", type=Path, nargs="+", required=True)
    replay.add_argument("--max-runtime-seconds", type=int, required=True)
    replay.add_argument("--output", type=Path, required=True)
    reconcile = commands.add_parser("reconcile", help="Read commit evidence for an explicit plan; never retry")
    reconcile.add_argument("--config", type=Path, required=True)
    reconcile.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = dict(status="verified", files=len(verified_target(args.target_root)),
                          network_used=False, database_used=False)
        elif args.command == "inspect-transport":
            collector=load_transport(args.target_root)
            result=dict(status="verified",files=2,index_pattern=collector.INDEX_PATTERN,network_used=False,database_used=False)
        elif args.command == "capture":
            result = collect(args)
        elif args.command == "plan":
            result = generate_plan(args)
        elif args.command == "replay":
            from p24_foundation.replay import replay_plans
            result = replay_plans(config=args.config, plans=args.plans,
                max_runtime_seconds=args.max_runtime_seconds, output=args.output,
                publish_command=[sys.executable, str(Path(__file__).resolve())])
        elif args.command == "reconcile":
            from p24_foundation.config import read_config, connect
            from p24_foundation.replay import inspect_plan_commit
            plan = load_plan(args.plan)
            settings = read_config(args.config)
            with connect(settings["database"]) as connection:
                result = inspect_plan_commit(connection, settings["namespace"], plan)
        else:
            from p24_foundation.config import read_config, connect
            from p24_foundation.privacy import Keys
            from p24_foundation.store import FoundationStore
            plan = load_plan(args.plan)
            settings = read_config(args.config)
            with connect(settings["database"]) as connection:
                store = FoundationStore(connection, Keys.read(settings["keys_path"]),
                                        settings["namespace"], settings["vault_path"])
                result = publish_plan(store, plan)
            result["status"] = "published"
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0 if result["status"] in {"verified", "captured", "planned", "published", "completed", "inspected"} else 2
    except FoundationError as error:
        print(json.dumps(dict(status="FAIL", error=error.code)))
        return 2
    except Exception:
        print(json.dumps(dict(status="FAIL", error="collector_operation_failed")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
