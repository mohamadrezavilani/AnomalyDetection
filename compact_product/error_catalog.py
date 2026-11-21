"""Versioned workbook definitions, imported once; never infer service or outcome."""

import hashlib
import json
from pathlib import Path
from psycopg.types.json import Jsonb

BASE_SHA256 = "c7dd443e34f24e3965c5f6e4e11b76fd747d33766823554cdaa3b1b8d1ca427e"
CATALOG_VERSION = "p24-compact-error-catalog-20261121-1"
# Current owner-supplied workbooks: all 1,925 code rows were compared with
# the archived catalog. Only GD2148 gains a definition; other cells match.
SOURCE_UPDATES = {
    "WebCrawler-ErrorCodes.xlsx": "121816bb185859202a9b275fa786513966f29bde4de9861925280f48a5273690",
    "CarAnnualTax-ErrorCodes.xlsx": "c79027e6a2244b336ce9b737bf61b4f18384ca83a4538116711869543a5bc614",
}


def catalog_records(root=None):
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    raw = (root / "catalogs/error_code_catalog.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_SHA256:
        raise ValueError("error_catalog_source_bytes_changed")
    records = json.loads(raw)["records"]
    for row in records:
        row["source_sha256"] = SOURCE_UPDATES.get(row["source_file"], row["source_sha256"])
        if row["entry_id"] == "WebCrawler:WebCrawler:149":
            row.update(
                user_message_fa="مشتری گرامی به جهت قطع (یکطرفه) تلفن شماره امکان استعلام پایان دوره وجود ندارد.",
                log_symbol="FixedLineExtendedBillInquiryFailedDueToDisconnectedStatus",
                definition_state="complete_definition",
            )
    return records


def ensure_catalog(db, schema):
    """Called inside runtime_init's schema-locked transaction, once per startup.

    COPY and the import receipt commit together. A rollback/restart retries the
    whole version. Existing versions stay available; no per-window writes.
    """
    db.execute(f"""CREATE TABLE IF NOT EXISTS {schema}.error_catalog_imports(
        version TEXT PRIMARY KEY, row_count INTEGER NOT NULL, imported_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS {schema}.error_code_definitions(
        version TEXT NOT NULL, entry_id TEXT NOT NULL, code TEXT NOT NULL,
        code_system TEXT NOT NULL, message_fa TEXT, log_symbol TEXT,
        definition_state TEXT NOT NULL, source JSONB NOT NULL,
        PRIMARY KEY(version,entry_id))""")
    db.execute(f"CREATE INDEX IF NOT EXISTS error_code_lookup ON {schema}.error_code_definitions(version,code)")
    if db.execute(f"SELECT 1 FROM {schema}.error_catalog_imports WHERE version=%s", (CATALOG_VERSION,)).fetchone():
        return False
    records = catalog_records()
    with db.cursor().copy(f"COPY {schema}.error_code_definitions(version,entry_id,code,code_system,message_fa,log_symbol,definition_state,source) FROM STDIN") as copy:
        for row in records:
            copy.write_row((CATALOG_VERSION, row["entry_id"], row["code"], row["code_system"],
                row["user_message_fa"], row["log_symbol"], row["definition_state"],
                Jsonb(dict(file=row["source_file"], sheet=row["source_sheet"], row=row["source_row"], sha256=row["source_sha256"])) ))
    db.execute(f"INSERT INTO {schema}.error_catalog_imports(version,row_count) VALUES(%s,%s)", (CATALOG_VERSION,len(records)))
    return True


def definitions(db, schema, codes):
    """Two bounded, read-only queries per page, not per behavior or payload."""
    codes = sorted({str(code) for code in codes if code})
    if not codes:
        return {}
    # Supports pre-upgrade schemas in read-only clients without DDL on GET.
    if not db.execute("SELECT to_regclass(%s) AS name", (schema + ".error_code_definitions",)).fetchone()["name"]:
        return {}
    rows = db.execute(f"""SELECT code,code_system,message_fa,log_symbol,definition_state,source
        FROM {schema}.error_code_definitions WHERE version=%s AND code=ANY(%s)
        ORDER BY code,code_system,entry_id""", (CATALOG_VERSION,codes)).fetchall()
    result = {}
    for row in rows:
        result.setdefault(row["code"], []).append(row)
    return result
