# Pishkhan24 — Compact Behavior and Independent AD

The owner and manager changed the product scope on 21 November 2026: extract observed API executions with the input, output and features needed for behavior analysis. Raw-log archival, financial relationship reconstruction and migration of the old anomaly models are outside the new product scope. RequestID identity, authoritative Session continuity, explicit uncertainty and late corrections remain required.

Start with the [current Persian roadmap](Pishkhan24_Project_Roadmap.md), then the [compact behavior contract, execution guide and qualification results](compact_behavior/README_FA.md).

## Current delivery

`compact_behavior/` implements the independent path:

`Elasticsearch -> bounded in-memory extraction -> compact PostgreSQL behavior and payload tables`

Behavior changes, dirty-window notifications and the independent checkpoint commit atomically in the `p24_compact` schema. The extraction/storage core does not import or read the legacy Viewer/AD. The Windows benchmark controller uses the installed application's process-control helpers to stop and restore existing roles.

The extraction/storage gate passed on the owner's Windows server with PostgreSQL 18.6: three fresh Elasticsearch windows, 214,911 source documents and 45,051 observed public-API behaviors. Per-window times were 22.250, 22.921 and 21.547 seconds; the entire child process took 67.110 seconds. Exact unique-document counts and empty terminal scroll pages were verified. All original roles were restored and legacy cursors stayed unchanged during the trial.

This is a successful small prototype gate. The compact schema initially contained no behaviors; the new UI, independent AD consumer/baselines, continuous operation and representative-history capacity are still pending. The observed short-run rate is not production acceptance with AD and web. Content extraction coverage, pending lifecycle and dirty consumption must be completed before continuous cutover.

The qualified runtime is `COMPACT-PROTOTYPE-20261121-4`, package SHA256 `4970eb9a4dfcdeeded2f77b306d57085370714eb4ebeb5fa3014b2e537c9f294`. The 56 compact tests passed locally and in native PostgreSQL CI; Linux and Windows compact checks passed as well. The separate existing Viewer regression workflow also passed. See the Persian guide for evidence identifiers, timing scope and remaining limitations.

## Existing application

`p24_foundation/`, `review_ui/`, `viewer_performance/` and `AnomalyDetection/` retain the installed Viewer/AD implementation and operational tooling. They are not switched over by merging this prototype. Their operational guides are [VIEWER_README_FA.md](VIEWER_README_FA.md) and [AnomalyDetection/README_FA.md](AnomalyDetection/README_FA.md); financial or historical acceptance requirements in older material do not override the current roadmap.

Use the existing Python 3.12 environment and private `viewer_config.local.py`. No credentials, source documents or complete operational report bundles are included in the repository.

```text
python -B -m unittest -v tests.test_compact_extract tests.test_compact_trial
```

Native PostgreSQL tests additionally require `P24_DELTA_PG_HOST`, `P24_DELTA_PG_PORT`, `P24_DELTA_PG_USER` and connection authentication; run `tests.test_compact_pg` in the same environment. The Windows owner-server benchmark command and recovery procedure are in the compact guide.
