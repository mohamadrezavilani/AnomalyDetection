"""C3 qualification: exact text keys for indexed transaction-local caches.

The binary-key accelerator is needed on permanent evidence indexes. Cached
origin validity and projection links already have full-text key indexes in
TEMP; decoding both operands on every probe adds no identity information.
Parenthesized exact equality keeps those local indexes and prevents the
generic permanent-key qualifier from adding the redundant decoder there.
Permanent event/raw probes and global version-cache construction are intact.
"""
from p24_foundation.viewer_data import ViewerDB
from .contract_fetch_once import ContractFetchOnceDB

MARKER='/* capacity_local_text_keys_v1 */'


def exact_cached_keys(statement,alias='e',*,origin_occurrences=1,version_occurrences=0):
    pairs=[('v.origin_key='+alias+'.origin_key','(v.origin_key)=('+alias+'.origin_key)',origin_occurrences),
        ('v.only_version_key='+alias+'.version_key','(v.only_version_key)=('+alias+'.version_key)',version_occurrences)]
    for original,replacement,expected in pairs:
        if statement.count(original)!=expected:raise ValueError('local_projection_query_shape_changed')
        if expected:statement=statement.replace(original,replacement)
    return statement+' '+MARKER


class LocalProjectionKeysDB(ContractFetchOnceDB):
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        self.local_key_queries=0

    def sql(self,statement,params=()):
        if MARKER in statement:self.local_key_queries+=1
        return super().sql(statement,params)

    @staticmethod
    def _global_conflict_predicate(indexed=False,cached=False):
        statement=ViewerDB._global_conflict_predicate(indexed=indexed,cached=cached)
        return exact_cached_keys(statement) if cached else statement

    @staticmethod
    def _single_version_origin_sql(alias='e',*,indexed=False,cached=False):
        statement=ViewerDB._single_version_origin_sql(alias,indexed=indexed,cached=cached)
        return exact_cached_keys(statement,alias,version_occurrences=1) if cached else statement

    @staticmethod
    def _request_aggregate_sql(events,*,scoped=False,indexed_conflict=False,cached=False):
        statement=ViewerDB._request_aggregate_sql(events,scoped=scoped,indexed_conflict=indexed_conflict,cached=cached)
        return exact_cached_keys(statement) if cached else statement

    @staticmethod
    def _request_roots_sql(events,*,scoped=False,indexed_conflict=False,cached=False):
        statement=ViewerDB._request_roots_sql(events,scoped=scoped,indexed_conflict=indexed_conflict,cached=cached)
        return exact_cached_keys(statement,origin_occurrences=2) if cached else statement

    @classmethod
    def _access_session_conflicts_sql(cls,events,*,scoped=False,indexed=False,cached=False,compact=False):
        statement=super()._access_session_conflicts_sql(events,scoped=scoped,indexed=indexed,cached=cached,compact=compact)
        if cached:
            for column in ('origin_key','version_key'):
                original='l.'+column+'=e.'+column
                if statement.count(original)!=1:raise ValueError('local_projection_link_query_shape_changed')
                statement=statement.replace(original,'(l.'+column+')=(e.'+column+')')
        return statement

    def candidate_report(self):
        return {**super().candidate_report(),
            'local_projection_keys':dict(queries=self.local_key_queries,
                permanent_binary_probes_unchanged=True,global_version_cache_unchanged=True,
                cache_survives_commit=False)}
