"""Independent identity; importing these tools cannot select a product writer."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BUILD='VIEWER-FINANCIAL-SCOPE-SCREEN-1'


def source_identity(root=ROOT):
    root=Path(root)
    paths=sorted((root/'viewer_performance/financial_screen').glob('*.py'))
    paths += [root/'viewer_performance/Screen_Financial_Product.py',
        root/'viewer_performance/Invoke_Financial_Screen.ps1']
    files={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    return dict(build=BUILD,files_sha256=files,source_sha256=hashlib.sha256(
        json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest())
