"""Small transactional invalidation tokens for paged source readers.

An unrelated publication cannot invalidate a historical population. A changed
request touches all its retained event windows and old/new semantic anchors.
Maintenance keeps a conservative global token. No evidence is rewritten here.
"""
FIVE_NS=300_000_000_000
CONTRACT='viewer-window-epochs-1'


def initialize(db):
    db.sql('''CREATE TABLE IF NOT EXISTS viewer_window_epoch_state(
        id INTEGER PRIMARY KEY CHECK(id=1),contract TEXT NOT NULL,maintenance_epoch BIGINT NOT NULL)''')
    db.sql('''CREATE TABLE IF NOT EXISTS viewer_window_epochs(
        start_ns BIGINT PRIMARY KEY,revision BIGINT NOT NULL)''')
    db.sql('INSERT INTO viewer_window_epoch_state VALUES(1,?,0) ON CONFLICT(id) DO NOTHING',(CONTRACT,))
    row=db.one('SELECT contract FROM viewer_window_epoch_state WHERE id=1')
    if row['contract']!=CONTRACT:raise ValueError('unknown_window_epoch_contract')
    db._window_epochs_ready=True


def active(db):
    if not hasattr(db,'_window_epochs_ready'):
        query=("SELECT name AS present FROM sqlite_master WHERE type='table' AND name='viewer_window_epoch_state'"
            if db.sqlite else "SELECT to_regclass('public.viewer_window_epoch_state') AS present")
        row=db.one(query);db._window_epochs_ready=bool(row and row['present'])
    return db._window_epochs_ready


def maintenance(db):
    if getattr(db,'_publication_epoch_windows',None) is None and active(db):
        db.sql('UPDATE viewer_window_epoch_state SET maintenance_epoch=maintenance_epoch+1 WHERE id=1')


def anchors(db,values):
    windows=getattr(db,'_publication_epoch_windows',None)
    if windows is not None:
        windows.update(at//FIVE_NS*FIVE_NS for at in values if type(at) is int and at>0)


def projection_events(db):
    if getattr(db,'_publication_epoch_windows',None) is not None:
        # This is the transaction-local request event cache, already populated
        # by rebuild. Never rescan the permanent evidence tables for a token.
        rows=db.all('SELECT DISTINCT (at_ns / ?)*? AS start_ns FROM viewer_projection_events WHERE at_ns>0',
                    (FIVE_NS,FIVE_NS))
        anchors(db,(r['start_ns'] for r in rows))


def publish(db,start,*,bootstrap=False):
    if not active(db):raise ValueError('window_epochs_not_initialized')
    if bootstrap:
        db.sql('UPDATE viewer_window_epoch_state SET maintenance_epoch=maintenance_epoch+1 WHERE id=1')
    windows=sorted(set(getattr(db,'_publication_epoch_windows',()) or ())|{start})
    statement='INSERT INTO viewer_window_epochs VALUES(?,1) ON CONFLICT(start_ns) DO UPDATE SET revision=viewer_window_epochs.revision+1'
    cursor=db.conn.cursor()
    try:cursor.executemany(statement if db.sqlite else statement.replace('?',db.param),[(at,) for at in windows])
    finally:cursor.close()
