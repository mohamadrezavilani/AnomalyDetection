"""Atomic small control files; domain data lives exclusively in PostgreSQL."""
import json
from pathlib import Path
import uuid


def atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)
