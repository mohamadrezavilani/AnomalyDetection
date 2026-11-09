"""Finite supervision of explicit publication plans; no automatic retry/resume."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from .errors import FoundationError
from .time import microsecond_cutoff

MAX_RESULT_BYTES = 65536


def inspect_plan_commit(connection, namespace, plan):
    """Read the commit ledger at the plan's generation, including superseded heads.

    Matching content cannot identify which publishing process committed it.
    This is evidence for manual reconciliation, never permission to retry.
    No FoundationStore is constructed: its namespace initializer writes.
    """
    target = plan["expected_generation"] + 1
    result = {"status": "inspected", "generation_inspected": target,
              "commit_found": False, "current_generation": 0,
              "planned_captures": len(plan["captures"]),
              "automatic_retry_authorized": False, "read_only": True}
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        row = connection.execute("SELECT namespace_id FROM p24_next.namespace WHERE application_key=%s",
                                 (namespace,)).fetchone()
        if row is None:
            result["assessment"] = "namespace_not_found"
            return result
        namespace_id = row[0]
        current = connection.execute("SELECT generation FROM p24_next.foundation_observation_current WHERE namespace_id=%s",
                                     (namespace_id,)).fetchone()
        result["current_generation"] = current[0] if current else 0
        committed = connection.execute("""SELECT p.publication_id,p.input_manifest,p.state
            FROM p24_next.foundation_observation_commit c
            JOIN p24_next.foundation_observation_publication p USING(namespace_id,publication_id)
            WHERE c.namespace_id=%s AND c.generation=%s""", (namespace_id, target)).fetchone()
        if committed is None:
            result["assessment"] = "no_commit_observed_at_read_time"
            return result
        publication, manifest, state = committed
        result.update(commit_found=True, publication_id=str(publication))
        sources = manifest["effective_sources"]
        if len(sources) > 128 or state != "sealed":
            raise FoundationError("collector_reconciliation_invalid_commit")
        rows = connection.execute("""SELECT snapshot_id,window_key,source_digest FROM p24_next.source_snapshot
            WHERE namespace_id=%s AND snapshot_id=ANY(%s)""",
            (namespace_id, [uuid.UUID(str(source)) for source in sources])).fetchall()
        selected = {}
        for snapshot, window, digest in rows:
            if window in selected:
                raise FoundationError("collector_reconciliation_ambiguous_sources")
            selected[window] = digest
        import hashlib
        matches = sum(selected.get(item["source_key"]) == hashlib.sha256(item["batch"].original).hexdigest()
                      for item in plan["captures"])
        cutoff_matches = manifest.get("event_cutoff_ns") == str(microsecond_cutoff(plan["event_cutoff"]).epoch_ns)
        result.update(matching_selected_captures=matches, event_cutoff_matches=cutoff_matches,
            assessment="planned_content_observed" if matches == len(plan["captures"]) and cutoff_matches
                       else "different_committed_content")
    return result


def _write_report(path, report, *, create=False):
    """Install complete private bytes atomically; initial creation cannot clobber."""
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".replay-report-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if create:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    except FileExistsError:
        raise FoundationError("collector_replay_output_exists") from None
    except OSError:
        raise FoundationError("collector_replay_report_write_failed") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _published(raw, exit_code):
    """Accept only the success fields needed for reconciliation; discard extras."""
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        if len(raw) > MAX_RESULT_BYTES or exit_code != 0:
            return None
        value = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict) or value.get("status") != "published":
            return None
        publication = str(uuid.UUID(value["publication_id"]))
        generation = value["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            return None
        return {"publication_id": publication, "generation": generation}
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None


def replay_plans(*, config, plans, max_runtime_seconds, output, publish_command):
    """Run named plans in order; every started but unconfirmed step is uncertain.

    A private in-flight report is durable before each child starts. A killed
    supervisor therefore leaves a reconciliation warning rather than a false
    success/rollback claim. Publication keeps its existing database fence.
    """
    started = time.monotonic()
    if (isinstance(max_runtime_seconds, bool) or not isinstance(max_runtime_seconds, int)
            or not 1 <= max_runtime_seconds <= 3600 or not 1 <= len(plans) <= 128):
        raise FoundationError("invalid_collector_replay_bounds")
    output = Path(output)
    report = {"version": "p24-collector-replay.1", "run_id": str(uuid.uuid4()),
              "status": "running", "planned": len(plans), "steps": [],
              "max_runtime_seconds": max_runtime_seconds,
              "requires_reconciliation": False, "bounded": True,
              "production_modified": False}
    _write_report(output, report, create=True)
    deadline = started + max_runtime_seconds
    for ordinal, plan in enumerate(plans, 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            report["status"] = "deadline_reached"
            break
        step = {"ordinal": ordinal, "status": "outcome_unknown", "reason": "publication_in_progress"}
        report["steps"].append(step)
        report["requires_reconciliation"] = True
        _write_report(output, report)
        process = None
        try:
            # File-backed stdout avoids an unbounded PIPE allocation. Read only
            # one small result; stderr is never copied into the safe report.
            with tempfile.TemporaryFile() as stdout:
                command = list(publish_command) + ["publish", "--config", str(Path(config).resolve()),
                                                   "--plan", str(Path(plan).resolve())]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    step.update(status="not_started", reason="deadline_reached")
                    report["status"] = "deadline_reached"
                    report["requires_reconciliation"] = False
                    break
                process = subprocess.Popen(command, stdout=stdout, stderr=subprocess.DEVNULL, shell=False)
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
                stdout.seek(0)
                result = _published(stdout.read(MAX_RESULT_BYTES + 1), process.returncode)
                if result is None:
                    step.update(reason="publication_result_unconfirmed")
                    report["status"] = "stopped"
                    break
                step.clear()
                step.update(ordinal=ordinal, status="published", **result)
                report["requires_reconciliation"] = False
        except subprocess.TimeoutExpired:
            step["reason"] = "publication_deadline_exceeded"
            report["status"] = "stopped"
            break
        except KeyboardInterrupt:
            step["reason"] = "publication_interrupted"
            report["status"] = "stopped"
            break
        except Exception:
            if process is None:
                step.update(status="not_started", reason="publication_start_failed")
                report["requires_reconciliation"] = False
            else:
                step["reason"] = "publication_result_unconfirmed"
            report["status"] = "stopped"
            break
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()  # Reap before returning; cleanup may outlast the run deadline.
            _write_report(output, report)
    else:
        report["status"] = "completed"
    report["completed"] = sum(s["status"] == "published" for s in report["steps"])
    _write_report(output, report)
    return report
