"""PostgreSQL-only product connection and owned schema bootstrap. No fallback."""
from contextlib import contextmanager
from pathlib import Path
import secrets
import time
import uuid

from .pg_source import read_database_config
from .process_control import read_json,write_json
from .snapshot import require

SCHEMA='anomaly_detection'
ROLE='p24_anomaly_detection'

def source_parameters(project):
    """Use our installed role for every source read, never the bootstrap user."""
    credentials=read_json(Path(project)/'AnomalyDetection/data/pg_credentials.local.json',None)
    require(credentials and credentials['connection'].get('user')==ROLE,'SOURCE_SELECT_ROLE_NOT_PREPARED')
    return dict(credentials['connection'])

def prepare_source_reader(root,raw,database,tag):
    missing=raw.execute("SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m') AND c.relname LIKE 'viewer_%%' "
        "AND NOT has_table_privilege(current_user,c.oid,'SELECT')").fetchall()
    if not missing:return raw
    import psycopg
    from psycopg import sql
    with psycopg.connect(**database,autocommit=True) as admin:
        role=admin.execute("SELECT shobj_description(oid,'pg_authid') AS tag FROM pg_catalog.pg_roles WHERE rolname=%s",(ROLE,)).fetchone()
        actual=role['tag'] if isinstance(role,dict) else role[0] if role else None
        require(actual==tag,'OWNED_POSTGRES_ROLE_NAME_COLLISION')
        with admin.transaction():
            admin.execute(sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(sql.Identifier(ROLE)))
            for row in missing:
                admin.execute(sql.SQL('GRANT SELECT ON TABLE public.{} TO {}').format(sql.Identifier(row['relname']),sql.Identifier(ROLE)))
    return raw


def connect(root, *, readonly=False):
    import psycopg
    from psycopg.rows import dict_row
    root=Path(root)
    credentials=read_json(root/'data/pg_credentials.local.json',None)
    require(credentials is not None,'POSTGRESQL_CREDENTIALS_NOT_PREPARED')
    params=dict(credentials['connection'])
    require(params.get('dbname')=='p24_design_viewer' and params.get('user')==ROLE,'OWNED_POSTGRES_IDENTITY_MISMATCH')
    for field in ('options','row_factory','autocommit','application_name','service','passfile'): params.pop(field,None)
    params.update(connect_timeout=3,application_name='AnomalyDetection.Product'+('.web' if readonly else '.worker'),
        options='-c search_path=anomaly_detection,pg_catalog -c synchronous_commit=on -c statement_timeout=3000 '
        '-c lock_timeout=150 -c idle_in_transaction_session_timeout=10000 -c jit=off '
        '-c max_parallel_workers_per_gather=0 -c work_mem=8MB -c default_transaction_read_only='+('on' if readonly else 'off'))
    raw=psycopg.connect(**params,autocommit=True,row_factory=dict_row)
    try:
        row=raw.execute('SELECT current_database() AS db,current_user AS role').fetchone()
        require(row['db']=='p24_design_viewer' and row['role']==ROLE,'OWNED_POSTGRES_IDENTITY_MISMATCH')
        flags=raw.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user').fetchone()
        require(flags and not any(flags.values()),'OWNED_POSTGRES_ROLE_HAS_EXCESS_PRIVILEGES')
        unwanted=raw.execute("SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relkind IN ('r','p','v') AND c.relname LIKE 'viewer_%%' "
            "AND has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') LIMIT 1").fetchone()
        require(unwanted is None,'OWNED_ROLE_INHERITS_SOURCE_WRITE_PRIVILEGE')
        return raw
    except BaseException: raw.close();raise


def prepare(root):
    """Use existing credentials, or create only our role/schema for a new install."""
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
    root=Path(root); path=root/'data/pg_credentials.local.json'
    saved=read_json(path,None)
    if saved is None:
        database=read_database_config(root.parent/'viewer_config.local.py')
        own=dict(database,user=ROLE,password=secrets.token_urlsafe(36))
        for field in ('options','row_factory','autocommit','application_name','service','passfile'): own.pop(field,None)
        saved={'format':1,'installation_id':uuid.uuid4().hex,'connection':own}
        write_json(path,saved)
        try:path.chmod(0o600)
        except OSError:pass
    database=read_database_config(root.parent/'viewer_config.local.py')
    for field in ('options','row_factory','autocommit','application_name','service','passfile'):database.pop(field,None)
    database.update(connect_timeout=3,application_name='AnomalyDetection.Product.bootstrap',
        options='-c statement_timeout=3000 -c lock_timeout=150 -c synchronous_commit=on')
    tag='AnomalyDetection:'+saved['installation_id']
    # Existing installs can start without using bootstrap privileges again.
    try:
        raw=connect(root)
        namespace=raw.execute("SELECT obj_description(oid,'pg_namespace') AS tag FROM pg_catalog.pg_namespace WHERE nspname=%s",(SCHEMA,)).fetchone()
        if namespace is not None:
            require(namespace['tag']==tag,'OWNED_POSTGRES_SCHEMA_NAME_COLLISION')
            return prepare_source_reader(root,raw,database,tag)
        raw.close()
    except Exception as exc:
        if 'raw' in locals():raw.close()
        if getattr(exc,'sqlstate',None) not in ('28000','28P01','3F000') and type(exc).__name__ not in ('OperationalError',):raise
    with psycopg.connect(**database,autocommit=True,row_factory=dict_row) as admin:
        role=admin.execute("SELECT shobj_description(oid,'pg_authid') AS tag FROM pg_catalog.pg_roles WHERE rolname=%s",(ROLE,)).fetchone()
        namespace=admin.execute("SELECT obj_description(oid,'pg_namespace') AS tag FROM pg_catalog.pg_namespace WHERE nspname=%s",(SCHEMA,)).fetchone()
        require(role is None or role['tag']==tag,'OWNED_POSTGRES_ROLE_NAME_COLLISION')
        require(namespace is None or namespace['tag']==tag,'OWNED_POSTGRES_SCHEMA_NAME_COLLISION')
        with admin.transaction():
            if role is None:
                admin.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 6 PASSWORD {}').format(sql.Identifier(ROLE),sql.Literal(saved['connection']['password'])))
                admin.execute(sql.SQL('COMMENT ON ROLE {} IS {}').format(sql.Identifier(ROLE),sql.Literal(tag)))
            admin.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO {}').format(sql.Identifier('p24_design_viewer'),sql.Identifier(ROLE)))
            if namespace is None:
                admin.execute(sql.SQL('GRANT CREATE ON DATABASE {} TO {}').format(sql.Identifier('p24_design_viewer'),sql.Identifier(ROLE)))
    raw=connect(root)
    try:
        if namespace is None:
            with raw.transaction():
                raw.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(SCHEMA)))
                raw.execute(sql.SQL('COMMENT ON SCHEMA {} IS {}').format(sql.Identifier(SCHEMA),sql.Literal(tag)))
        with psycopg.connect(**database,autocommit=True) as admin:
            admin.execute(sql.SQL('REVOKE CREATE ON DATABASE {} FROM {}').format(sql.Identifier('p24_design_viewer'),sql.Identifier(ROLE)))
        return prepare_source_reader(root,raw,database,tag)
    except BaseException:raw.close();raise


@contextmanager
def database(root, *, readonly=False):
    raw=connect(root,readonly=readonly)
    try:yield raw
    finally:raw.close()
