"""Explicit byte identities for audited Viewer releases, never wildcard pins.

R3.1 is the supplied complete R3 tree with only the supplied viewer_data.py
overlay. Its root manifest was intentionally left historical by that overlay.
No other file change, partial Git tree or unknown manifest is accepted.
R3.2 changes dependency access and session-head maintenance only. It has its
own complete root manifest; it never borrows the historical R3 overlay rule.
Native SQL/throughput qualification is separate from this byte compatibility.
"""
R3_RUNTIME='84e9dcc984092735dd4785a26b5af02019eda63d0d5d7ee221bb0c84da37e993'
R31_RUNTIME='e132996f9f68f3b8f7ed899af27d1b8b98aa9caa9517f69e04869029f45f80c7'
R31_VIEWER_DATA='603d90df89184dc0625966541a59fdfbb656a1c278b7191d418c7822df5ad4bb'
R31_FILES=180
R32_RUNTIME='c4c08bdf4b0165e6c253b5f934128edca7418e573e9fc4f698e03349752b19ee'
R32_FILES=180
R33_RUNTIME='7664ee33a6f2be3257796f9b53780e9b1a1e6d06e37f7022bed46ca66cbbce55'
R33_FILES=180
R34_RUNTIME='2c4e413ef8c6890ae720c574d63eb6b4f0218d36c1d6350371c0c820df09f5e0'
R34_FILES=180
R35_RUNTIME='f992eb57d6d53cc205aac9f25b03deee1bc3bc606ff56b701fb213ead04e35da'
R35_FILES=181
R36_RUNTIME='ffb883f6f8cc8deef5a8aa104b39186d4ed60ede1605695f5b9f267fcf4bbd33'
R36_FILES=182
SUPPORTED_RUNTIMES=frozenset((R3_RUNTIME,R31_RUNTIME,R32_RUNTIME,R33_RUNTIME,R34_RUNTIME,R35_RUNTIME,R36_RUNTIME))


def r31_overlay_allowed(manifest_runtime,actual_runtime,file_count,viewer_data_sha):
    return bool(manifest_runtime in (R3_RUNTIME,R31_RUNTIME) and actual_runtime==R31_RUNTIME
        and file_count==R31_FILES and viewer_data_sha==R31_VIEWER_DATA)


def r32_release_allowed(manifest_runtime,actual_runtime,file_count):
    return bool(manifest_runtime==R32_RUNTIME and actual_runtime==R32_RUNTIME and file_count==R32_FILES)


def r33_release_allowed(manifest_runtime,actual_runtime,file_count):
    return bool(manifest_runtime==R33_RUNTIME and actual_runtime==R33_RUNTIME and file_count==R33_FILES)


def r34_release_allowed(manifest_runtime,actual_runtime,file_count):
    return bool(manifest_runtime==R34_RUNTIME and actual_runtime==R34_RUNTIME and file_count==R34_FILES)


def r35_release_allowed(manifest_runtime,actual_runtime,file_count):
    return bool(manifest_runtime==R35_RUNTIME and actual_runtime==R35_RUNTIME and file_count==R35_FILES)


def r36_release_allowed(manifest_runtime,actual_runtime,file_count):
    return bool(manifest_runtime==R36_RUNTIME and actual_runtime==R36_RUNTIME and file_count==R36_FILES)
