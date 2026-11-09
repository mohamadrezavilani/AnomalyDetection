"""Explicit local configuration and disposable-database guard. No env discovery."""
from __future__ import annotations

import re
import runpy
import os
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path

from .errors import FoundationError

ALLOWED_DATABASE = re.compile(r"^p24_design_[a-z0-9_]{1,48}$")

def validate_database_config(value):
    if not isinstance(value, dict):
        raise FoundationError("invalid_database_configuration")
    allowed = {"host", "port", "dbname", "user", "password", "connect_timeout"}
    if set(value) - allowed:
        raise FoundationError("unsupported_database_option")
    if value.get("host") not in {"127.0.0.1", "::1", "localhost"}:
        raise FoundationError("database_requires_loopback")
    if not ALLOWED_DATABASE.fullmatch(str(value.get("dbname", ""))):
        raise FoundationError("database_requires_disposable_name")
    if isinstance(value.get("port", 5432), bool) or not isinstance(value.get("port", 5432), int):
        raise FoundationError("invalid_database_port")
    if not 1 <= value.get("port", 5432) <= 65535:
        raise FoundationError("invalid_database_port")
    if not value.get("user"):
        raise FoundationError("database_user_required")
    if isinstance(value.get('connect_timeout',5),bool) or not isinstance(value.get('connect_timeout',5),int):
        raise FoundationError('invalid_database_connect_timeout')
    return {**value, "connect_timeout": min(max(int(value.get("connect_timeout", 5)), 1), 30)}

def read_config(path):
    path = Path(path).resolve()
    try:
        with open(os.devnull,'w') as sink,redirect_stdout(sink),redirect_stderr(sink):
            value = runpy.run_path(str(path))
    except FileNotFoundError:
        raise FoundationError('local_configuration_file_missing') from None
    except PermissionError:
        raise FoundationError('local_configuration_not_readable') from None
    except SyntaxError:
        raise FoundationError('local_configuration_syntax_error') from None
    except Exception:
        raise FoundationError('local_configuration_execution_failed') from None
    try:
        for name in ('DATABASE','NAMESPACE','KEYS_PATH','VAULT_PATH'):
            if name not in value:
                raise FoundationError('configuration_missing_'+name.lower())
        database = validate_database_config(value["DATABASE"])
        namespace = value["NAMESPACE"]
        if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", namespace):
            raise FoundationError("invalid_namespace")
        def local(name):
            if not isinstance(value[name],(str,Path)) or not str(value[name]):
                raise FoundationError('invalid_configuration_path')
            p = Path(value[name])
            return p if p.is_absolute() else path.parent / p
        access_key = local("ACCESS_PUBLIC_KEY_PATH") if value.get("ACCESS_PUBLIC_KEY_PATH") else None
        issuer = value.get("ACCESS_ISSUER", "p24-foundation-local")
        audience = value.get("ACCESS_AUDIENCE", "p24-evidence-inspection")
        if not isinstance(issuer,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}",issuer):
            raise FoundationError("invalid_access_issuer")
        if not isinstance(audience,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}",audience):
            raise FoundationError("invalid_access_audience")
        return dict(database=database, namespace=namespace, keys_path=local("KEYS_PATH"), vault_path=local("VAULT_PATH"),
                    access_public_key_path=access_key, access_issuer=issuer, access_audience=audience)
    except FoundationError:
        raise
    except Exception:
        raise FoundationError("invalid_local_configuration") from None


def connection_error_code(error):
    """Classify startup failures without copying driver messages or credentials."""
    if isinstance(error,FoundationError):
        return error.code
    code=getattr(error,'sqlstate',None)
    if isinstance(code,str) and code.startswith('28'):
        return 'database_authentication_failed'
    if code=='3D000':
        return 'database_not_found'
    return 'database_connection_failed'

def connect(database):
    import psycopg
    database = validate_database_config(database)
    connection = psycopg.connect(**database, autocommit=True)
    try:
        actual = connection.execute("SELECT current_database()").fetchone()[0]
        if actual != database["dbname"] or not ALLOWED_DATABASE.fullmatch(actual):
            raise FoundationError("database_identity_mismatch")
        connection.execute("SET TIME ZONE 'UTC'")
        connection.execute("SET statement_timeout = '30s'")
        connection.execute("SET lock_timeout = '5s'")
        return connection
    except Exception:
        connection.close()
        raise

