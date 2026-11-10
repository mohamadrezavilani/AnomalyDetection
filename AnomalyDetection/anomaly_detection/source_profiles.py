"""Explicit byte identities for audited Viewer releases, never wildcard pins.

R3.1 is the supplied complete R3 tree with only the supplied viewer_data.py
overlay. Its root manifest was intentionally left historical by that overlay.
No other file change, partial Git tree or unknown manifest is accepted.
Native SQL/throughput qualification is separate from this byte compatibility.
"""
R3_RUNTIME='84e9dcc984092735dd4785a26b5af02019eda63d0d5d7ee221bb0c84da37e993'
R31_RUNTIME='e132996f9f68f3b8f7ed899af27d1b8b98aa9caa9517f69e04869029f45f80c7'
R31_VIEWER_DATA='603d90df89184dc0625966541a59fdfbb656a1c278b7191d418c7822df5ad4bb'
R31_FILES=180
SUPPORTED_RUNTIMES=frozenset((R3_RUNTIME,R31_RUNTIME))


def r31_overlay_allowed(manifest_runtime,actual_runtime,file_count,viewer_data_sha):
    return bool(manifest_runtime in (R3_RUNTIME,R31_RUNTIME) and actual_runtime==R31_RUNTIME
        and file_count==R31_FILES and viewer_data_sha==R31_VIEWER_DATA)
