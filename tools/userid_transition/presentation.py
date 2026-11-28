"""Set a durable per-stream publication fence on the preserved Compact database."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from psycopg import sql
from compact_behavior.store import stream_lock
from compact_product.config import load
from compact_product.performance import recent
from account_behavior.storage import connect


def _names(schema, stream):
    import hashlib
    table = sql.Identifier(schema, "windows")
    function = sql.Identifier(schema, "p24_stop_publication_" + hashlib.sha256(stream.encode()).hexdigest()[:14])
    trigger = "p24_presentation_" + hashlib.sha256(stream.encode()).hexdigest()[:14]
    return table, function, trigger


def freeze(db, schema, stream):
    """Use the publisher's own stream lock. A rejected window rolls back its complete transaction."""
    table, function, trigger = _names(schema, stream)
    with db.transaction():
        db.execute("SET LOCAL lock_timeout='90s'")
        db.execute("SELECT pg_advisory_xact_lock(%s)", (stream_lock(stream),))
        row = db.execute(sql.SQL("SELECT start_ns,next_ns,change_epoch FROM {} WHERE stream_id=%s").format(
            sql.Identifier(schema, "streams")), (stream,)).fetchone()
        if row is None:
            raise ValueError("existing_compact_stream_required")
        last = db.execute(sql.SQL("SELECT start_ns,end_ns FROM {} WHERE stream_id=%s ORDER BY start_ns DESC LIMIT 1").format(
            table), (stream,)).fetchone()
        if not last:
            raise ValueError("existing_committed_window_required")
        present = db.execute("""SELECT t.tgenabled FROM pg_trigger t WHERE t.tgrelid=to_regclass(%s)
                              AND t.tgname=%s AND NOT t.tgisinternal""", (schema+".windows",trigger)).fetchone()
        if present is None:
            db.execute(sql.SQL("""CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $fn$
                BEGIN RAISE EXCEPTION 'P24_PRESENTATION_INPUT_FROZEN' USING ERRCODE='55000'; END; $fn$""").format(function))
            db.execute(sql.SQL("""CREATE TRIGGER {} BEFORE INSERT OR UPDATE ON {} FOR EACH ROW
                               WHEN (NEW.stream_id = {}) EXECUTE FUNCTION {}()""").format(
                sql.Identifier(trigger),table,sql.Literal(stream),function))
            db.execute(sql.SQL("ALTER TABLE {} ENABLE ALWAYS TRIGGER {}").format(table,sql.Identifier(trigger)))
        elif present["tgenabled"] != "A":
            raise ValueError("presentation_trigger_disabled_or_altered")
        # Verify the actual installed rule on an existing row. A savepoint isolates the expected error.
        import psycopg
        try:
            with db.transaction():
                db.execute(sql.SQL("UPDATE {} SET end_ns=end_ns WHERE stream_id=%s AND start_ns=%s").format(
                    table), (stream,last["start_ns"]))
                raise ValueError("presentation_write_probe_was_not_rejected")
        except psycopg.Error as exc:
            if exc.sqlstate != "55000" or exc.diag.message_primary != "P24_PRESENTATION_INPUT_FROZEN":
                raise
        day = datetime.fromtimestamp(last["start_ns"] // 10**9, timezone.utc).astimezone(ZoneInfo("Asia/Tehran")).date()
        return dict(fenced=True, cursor_ns=row["next_ns"], epoch=row["change_epoch"], latest_end_ns=last["end_ns"],
                    review_path=f"/incidents?tab=cases&date={day.isoformat()}&days=30")


def apply(project, *, verify_only=False):
    cfg, settings, stream = load(project)
    with connect(settings["DATABASE"]) as db:
        if verify_only:
            # A second independent observer must not create or repair the guard it is checking.
            _, _, trigger = _names(cfg.source_schema, stream)
            guard = db.execute("SELECT tgenabled FROM pg_trigger WHERE tgrelid=to_regclass(%s) AND tgname=%s",
                               (cfg.source_schema+".windows",trigger)).fetchone()
            if not guard or guard["tgenabled"] != "A":
                raise ValueError("presentation_fence_not_active")
            return db.execute(sql.SQL("SELECT next_ns AS cursor_ns,change_epoch AS epoch FROM {} WHERE stream_id=%s")
                .format(sql.Identifier(cfg.source_schema,"streams")),(stream,)).fetchone()
        result = freeze(db, cfg.source_schema, stream)
        # Read the existing bounded telemetry, without rerunning previous software on the live data.
        with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            result["previous_performance"] = recent(db,cfg.source_schema,stream)
        return result


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project",required=True)
    parser.add_argument("--verify",action="store_true")
    args = parser.parse_args()
    print(json.dumps(apply(args.project,verify_only=args.verify),default=str,ensure_ascii=True))
