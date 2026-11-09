"""Read committed evidence, score Session/service activity, and write a private Persian report."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from p24_foundation.behavior import publication_window, score, window
from p24_foundation.errors import FoundationError
from p24_foundation.privacy import Keys
from p24_foundation.time import microsecond_cutoff


def demo_report():
    """Illustrate personal deviation with typed synthetic summaries, never real traffic."""
    keys = Keys(b"d" * 32, b"e" * 32, "synthetic")
    token = lambda route: keys.token("demo", "service", route)
    start = datetime(2026, 1, 2, tzinfo=timezone.utc)
    def build(at, counts):
        rows = []
        for actor, count in counts.items():
            for number in range(count):
                rows.append(dict(request_key=keys.token("demo", "request", [at.isoformat(), actor, number]),
                    session_key=keys.token("demo", "session", actor), identity_state="known", endpoint="demo-route",
                    activity_time_ns=str(microsecond_cutoff(at.isoformat()).epoch_ns + number),
                    client_completion_state="observed", distinct_client_request_count=1))
        end = at + timedelta(minutes=5)
        return window(at.isoformat(), end.isoformat(), microsecond_cutoff(end.isoformat()).epoch_ns,
                      uuid.uuid5(uuid.NAMESPACE_URL, at.isoformat()), rows, route_token=token)
    references = [build(start - timedelta(minutes=5 * n), {"ordinary": 2, "high-volume": 20}) for n in range(19, 0, -1)]
    report = score(build(start, {"ordinary": 20, "high-volume": 20}), references, rank_cutoff="1/20")
    report["input_kind"] = "synthetic_demo"
    report["demo_expectation"] = "one personal-volume candidate; ordinary high-volume actor stays within its own reference"
    return report


def read_references(path):
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        with path.open("rb") as stream:
            raw = stream.read(64001)
        if len(raw) > 64000:
            raise ValueError()
        items = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(items, list) or not 1 <= len(items) <= 128:
            raise ValueError()
        for item in items:
            if not isinstance(item, dict) or set(item) != {"publication_id", "start", "end"}:
                raise ValueError()
            uuid.UUID(item["publication_id"])
        return items
    except (ValueError, TypeError, OSError, AttributeError):
        raise FoundationError("invalid_behavior_reference_manifest") from None


def write_report(path, report, *, format="json"):
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".behavior-report-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            if format == "html":
                from jinja2 import Environment, FileSystemLoader
                environment = Environment(loader=FileSystemLoader(ROOT / "review_ui/templates"), autoescape=True)
                rows = sorted(report["evaluations"], key=lambda item: (item["status"] != "candidate", item["session_key"], item["service_key"]))
                stream.write(environment.get_template("behavior_report.html").render(report=report, rows=rows[:100], total_rows=len(rows)))
            else:
                json.dump(report, stream, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except FileExistsError:
        raise FoundationError("behavior_output_exists") from None
    except OSError:
        raise FoundationError("behavior_report_write_failed") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true")
    mode.add_argument("--config", type=Path)
    parser.add_argument("--target-publication")
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--references", type=Path)
    parser.add_argument("--rank-cutoff", help="Explicit descriptive rank policy, e.g. 1/20; no production default")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument("--persist-candidates", action="store_true", help="Explicit experimental candidate/incident writes in the guarded design database")
    parser.add_argument("--expected-generation", type=int, help="Required publication generation fence for persistence")
    args = parser.parse_args(argv)
    persistence_attempted = False
    try:
        if args.persist_candidates and (args.demo or args.expected_generation is None):
            raise FoundationError("behavior_persistence_arguments_required")
        if args.output.exists():
            raise FoundationError("behavior_output_exists")
        if args.demo:
            report = demo_report()
        else:
            if not all([args.target_publication, args.start, args.end, args.references, args.rank_cutoff]):
                raise FoundationError("behavior_arguments_required")
            from p24_foundation.config import connect, read_config
            settings = read_config(args.config)
            keys = Keys.read(settings["keys_path"])
            references = read_references(args.references)
            tokenize = lambda route: keys.token(settings["namespace"], "behavior_service", route)
            if args.persist_candidates:
                from p24_foundation.store import FoundationStore
                from p24_foundation.behavior_store import persist_candidates
                persistence_attempted = True
                with connect(settings["database"]) as connection, connection.transaction():
                    store = FoundationStore(connection, keys, settings["namespace"], settings["vault_path"])
                    report = persist_candidates(store,
                        target_spec=dict(publication_id=args.target_publication, start=args.start, end=args.end),
                        reference_specs=references, rank_cutoff=args.rank_cutoff, expected_generation=args.expected_generation)
            else:
                with connect(settings["database"]) as connection, connection.transaction():
                    connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    row = connection.execute("SELECT namespace_id FROM p24_next.namespace WHERE application_key=%s",
                                             (settings["namespace"],)).fetchone()
                    if row is None:
                        raise FoundationError("behavior_namespace_not_found")
                    binding = connection.execute("SELECT equality_key_fingerprint FROM p24_next.foundation_namespace_contract WHERE namespace_id=%s", (row[0],)).fetchone()
                    if not binding or binding[0] != keys.fingerprint:
                        raise FoundationError("namespace_contract_mismatch")
                    target = publication_window(connection, row[0], args.target_publication, args.start, args.end, route_token=tokenize)
                    history, reference_requests = [], 0
                    for ref in references:
                        item = publication_window(connection, row[0], ref["publication_id"], ref["start"], ref["end"], route_token=tokenize)
                        reference_requests += sum(len(values) for values in item["groups"].values())
                        if reference_requests > 100_000:
                            raise FoundationError("behavior_reference_request_limit")
                        history.append(item)
                    report = score(target, history, rank_cutoff=args.rank_cutoff)
                    report["input_kind"] = "committed_observed_publications"
        write_report(args.output, report, format=args.format)
        print(json.dumps(dict(status="reported", evaluated=report["evaluated_units"], abstained=report["unsupported_units"],
                              candidates=len(report["candidates"]), evidence_manifest_sha256=report["evidence_manifest_sha256"])))
        return 0
    except FoundationError as error:
        print(json.dumps(dict(status="FAIL", error=error.code, persistence_outcome="requires_reconciliation" if persistence_attempted else "not_attempted")))
        return 2
    except Exception:
        print(json.dumps(dict(status="FAIL", error="behavior_operation_failed", persistence_outcome="requires_reconciliation" if persistence_attempted else "not_attempted")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
