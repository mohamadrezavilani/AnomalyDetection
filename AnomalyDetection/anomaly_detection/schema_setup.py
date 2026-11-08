"""Inspect existing owned objects before issuing lock-taking schema DDL.

Only the fixed product DDL grammar is accepted. Existing objects are checked
through pg_catalog; a normal restart never executes redundant ALTER/CREATE.
Missing objects are still migrated in the caller's rollback-safe transaction.
"""
import re
from .snapshot import require

NAME=r'[a-z][a-z0-9_]*'
TYPES={'TEXT':'text','BIGINT':'bigint','INTEGER':'integer','BOOLEAN':'boolean','DOUBLE PRECISION':'double precision'}


def columns(body):
    # Product declarations contain no quoted identifiers or comma-containing
    # defaults. Split only commas outside the primary-key column list.
    parts=[];start=depth=0
    for i,char in enumerate(body):
        if char=='(':depth+=1
        elif char==')':depth-=1
        elif char==',' and depth==0:parts.append(body[start:i]);start=i+1
    parts.append(body[start:]);out={}
    for part in parts:
        part=part.strip()
        if part.startswith(('PRIMARY KEY','UNIQUE(','CONSTRAINT ')):continue
        match=re.fullmatch('('+NAME+r')\s+(DOUBLE PRECISION|TEXT|BIGINT|INTEGER|BOOLEAN)\b(.*)',part,re.S)
        require(match is not None,'PRODUCT_DDL_COLUMN_GRAMMAR_UNSUPPORTED')
        default=re.search(r"\bDEFAULT\s+('[^']*'|TRUE|FALSE|[0-9]+)",match[3])
        out[match[1]]={'type':TYPES[match[2]],'default':default[1] if default else None}
    return out


def declaration(query):
    table=re.fullmatch(r'CREATE TABLE IF NOT EXISTS anomaly_detection\.('+NAME+r')\((.*)\)',query,re.S)
    if table:return 'table',table[1],columns(table[2])
    index=re.fullmatch(r'CREATE INDEX IF NOT EXISTS ('+NAME+r') ON anomaly_detection\.('+NAME+r')\(.*',query,re.S)
    if index:return 'index',index[1],index[2]
    add=re.fullmatch(r'ALTER TABLE anomaly_detection\.('+NAME+r') ADD COLUMN IF NOT EXISTS (.*)',query,re.S)
    if add:return 'column',add[1],columns(add[2])
    default=re.fullmatch(r'ALTER TABLE anomaly_detection\.('+NAME+r') ALTER COLUMN ('+NAME+r") SET DEFAULT ('[^']*')",query)
    if default:return 'default',default[1],(default[2],default[3])
    require(False,'PRODUCT_DDL_GRAMMAR_OR_SCHEMA_UNSUPPORTED')


def inventory(raw,names):
    rows=raw.execute("SELECT c.relname,c.relkind,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod) AS column_type,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS column_default,i.indisvalid,i.indisready,t.relname AS indexed_table FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid LEFT JOIN pg_catalog.pg_class t ON t.oid=i.indrelid WHERE n.nspname='anomaly_detection' AND c.relname=ANY(%s)",(sorted(names),)).fetchall()
    tables={};indexes={}
    for row in rows:
        if row['relkind'] in ('r','p'):
            table=tables.setdefault(row['relname'],{})
            if row['attname']:table[row['attname']]={'type':row['column_type'],'default':row['column_default']}
        elif row['relkind'] in ('i','I'):indexes[row['relname']]={'table':row['indexed_table'],'valid':row['indisvalid'] and row['indisready']}
        else:require(False,'PRODUCT_SCHEMA_OBJECT_KIND_MISMATCH')
    return tables,indexes


def ensure(raw,statements):
    parsed=[declaration(q) for q in statements]
    tables,indexes=inventory(raw,{name for _,name,_ in parsed})
    additive={(table,col) for kind,table,cols in parsed if kind=='column' for col in cols}
    report={'statements':len(statements),'executed':0,'skipped_existing':0,'catalog_only_when_complete':True}
    for query,(kind,name,value) in zip(statements,parsed):
        needed=False
        if kind=='table':
            needed=name not in tables
            if not needed:
                for col,spec in value.items():
                    require(col in tables[name] or (name,col) in additive,'PRODUCT_EXISTING_SCHEMA_COLUMN_MISSING')
                    if col in tables[name]:require(tables[name][col]['type']==spec['type'],'PRODUCT_SCHEMA_COLUMN_TYPE_MISMATCH')
            else:tables[name]=value
        elif kind=='index':
            needed=name not in indexes
            if not needed:require(indexes[name]['table']==value and indexes[name]['valid'],'PRODUCT_SCHEMA_INDEX_NOT_READY_OR_MISMATCH')
            else:indexes[name]={'table':value,'valid':True}
        elif kind=='column':
            require(name in tables,'PRODUCT_SCHEMA_TABLE_MISSING')
            col,spec=next(iter(value.items()));needed=col not in tables[name]
            if not needed:require(tables[name][col]['type']==spec['type'],'PRODUCT_SCHEMA_COLUMN_TYPE_MISMATCH')
            else:tables[name][col]=spec
        else:
            col,expected=value
            require(name in tables and col in tables[name],'PRODUCT_SCHEMA_DEFAULT_COLUMN_MISSING')
            actual=tables[name][col]['default']
            needed=actual not in (expected,expected+'::text')
            if needed:tables[name][col]['default']=expected
        if needed:raw.execute(query);report['executed']+=1
        else:report['skipped_existing']+=1
    return report
