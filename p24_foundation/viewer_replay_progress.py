"""Read one committed replay cursor; never count the evidence tables for refresh."""


def replay_progress(db):
    from .viewer_online import FIVE_NS,iso
    if db.sqlite:
        present=db.one("SELECT name FROM sqlite_master WHERE type='table' AND name='viewer_history_replay_state'")
    else:
        present=db.one("SELECT to_regclass('public.viewer_history_replay_state') AS name")
    if not present or not present['name']:return None
    row=db.one('SELECT * FROM viewer_history_replay_state WHERE id=1')
    if not row:return None
    total=(row['end_ns']-row['from_ns'])//FIVE_NS
    checked=(row['next_ns']-row['from_ns'])//FIVE_NS
    # A persisted RUNNING plan is not proof of a live worker after a restart.
    active=None
    if not db.sqlite:
        active=db.one("""SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
            WHERE locktype='advisory' AND classid=240026 AND objid=1 AND objsubid=2
              AND mode='ExclusiveLock' AND granted
              AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())) AS active""")['active']
    pending=row['next_ns']<row['end_ns']
    return dict(status=row['status'],run_id=row['run_id'],publisher_active=active,
        from_utc=iso(row['from_ns']),checked_to_utc=iso(row['next_ns']),target_utc=iso(row['end_ns']),
        current_window_start_utc=iso(row['next_ns']) if pending else None,
        current_window_end_utc=iso(row['next_ns']+FIVE_NS) if pending else None,
        total_windows=int(total),checked_windows=int(checked),remaining_windows=int(total-checked),
        progress_percent=round(100*checked/total,1) if total else 100,
        published_missing_windows=row['published_windows'],skipped_complete_windows=row['skipped_windows'],
        last_progress_utc=iso(row['updated_ns']),ad_prepared=bool(row['ad_prepared']),ad_started=bool(row['ad_started']),
        remaining_includes_complete_windows=True)
