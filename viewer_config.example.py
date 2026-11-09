"""Copy to viewer_config.local.py, keep private; PostgreSQL viewer database only."""
DATABASE = {'host':'127.0.0.1','port':5432,'dbname':'p24_design_viewer','user':'postgres','password':None}
KEYS_PATH = 'private/viewer_keys.json'
# Development-only local unit/integration tests WITHOUT PostgreSQL:
# SQLITE_OFFLINE_PATH = 'private/viewer_offline.sqlite3'

# UTC, aligned to five minutes. Select once; the original stream binding stays fixed.
# Start with recent CLOSED windows; earlier history is not claimed complete.
LIVE_START_UTC = '2026-10-26T08:00:00Z'
ELASTICSEARCH = {
    'host': '',                    # e.g. http://your-existing-elastic-host:9200
    'index_pattern': '',           # same pattern as your existing fetcher
    'username': '', 'password': '',
    'verify_certs': True,
    'request_timeout_seconds': 60,
}
LIVE = {
    # Owner-requested DEBUG default, including old configs without this key:
    # each new `live` process seeks forward to the latest fully closed window.
    # Retained evidence stays; skipped windows are recorded as missing history.
    # False or Start_Viewer.cmd -ResumeCheckpoint restores ordinary continuity.
    'debug_recent_start': True,
    'capture_dir': 'private/viewer_captures',
    'lag_seconds': 60, 'overlap_windows': 2, 'poll_seconds': 30,
    'page_size': 5000, 'capture_budget_seconds': 240,
}
