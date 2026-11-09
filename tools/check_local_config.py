"""Check local Python settings and optionally ping; never echo config source/passwords."""
import argparse
import ast
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.config import read_config,connect,connection_error_code
from p24_foundation.errors import FoundationError


def check(path,*,ping=False):
    try:
        source=path.read_text(encoding='utf-8-sig')
        ast.parse(source)
    except SyntaxError as error:
        return dict(status='FAIL',stage='configuration',error='local_configuration_syntax_error',
                    line=error.lineno,column=error.offset)
    except FileNotFoundError:
        return dict(status='FAIL',stage='configuration',error='local_configuration_file_missing')
    except (OSError,UnicodeError):
        return dict(status='FAIL',stage='configuration',error='local_configuration_not_readable')
    try:
        settings=read_config(path)
    except FoundationError as error:
        return dict(status='FAIL',stage='configuration',error=error.code)
    result=dict(status='PASS',configuration='loaded',database=settings['database']['dbname'],
        host=settings['database']['host'],port=settings['database']['port'],
        password_configured=settings['database'].get('password') not in (None,''),
        database_connection='NOT_REQUESTED',private_keys_required_for_native_tests=False)
    if ping:
        try:
            with connect(settings['database']) as connection:
                result['postgres_server_version']=connection.execute('SHOW server_version_num').fetchone()[0]
            result['database_connection']='PASS'
        except Exception as error:
            result.update(status='FAIL',stage='database_connection',database_connection='FAIL',error=connection_error_code(error))
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=Path('db_config.local.py'))
    parser.add_argument('--ping',action='store_true')
    args=parser.parse_args(argv)
    try:
        result=check(args.config,ping=args.ping)
    except Exception:
        result=dict(status='FAIL',error='configuration_check_failed')
    print(json.dumps(result,separators=(',',':')))
    return 0 if result['status']=='PASS' else 2


if __name__=='__main__':
    raise SystemExit(main())
