# Pishkhan24 — Compact Behavior and Independent AD

The owner and manager changed the product scope on 21 November 2026: extract observed API executions with the input, output and features needed for behavior analysis. Raw-log archival, financial relationship reconstruction and migration of the old anomaly models are outside the new product scope. RequestID identity, authoritative Session continuity, explicit uncertainty and late corrections remain required.

Start with the [current Persian roadmap](Pishkhan24_Project_Roadmap.md) and [product contract, Windows deployment and rollback runbook](compact_product/README_FA.md).

The current candidate is `COMPACT-PRODUCT-20261121-5`: independent ingestion, eight explainable compact AD methods (model compact-ad-robust-2), version-fenced dirty consumption, pending lifecycle, manual-refresh web and supervised roles. It uses fresh `p24_compact_v2` / `p24_compact_ad_v2` schemas and fresh model references; legacy tables and feedback are retained.

Features preserve typed array multiplicity, explicit per-component completeness and selected-evidence parse validity. Nested duplicate JSON keys cannot silently overwrite targets. Empty object structure is represented. Both Core and Services AddUserData/GetUserData are automatic support observations, excluded from business-rate methods. InvoiceRegister dispatch requires reviewed same-request evidence.

Results and exact-version acknowledgements commit together. Timing confirmation belongs to the particular analysis revision, so a crash during a later correction cannot reuse an earlier fast timing. Freshness excludes pending reference reanalysis. Installation requires actual consumed publications, completed warmup, drained analysis work, confirmed latency, responsive web and a verified running supervisor.

Run the code from a fixed release worktree and pass the installed project's data/config path with `--project`. The Windows Task uses that same release code directory. The installer first checks and measures all three roles; it keeps the candidate only after its short gate and otherwise restores the previous roles. Defaults bind the manual-refresh UI to `0.0.0.0` on ports 5021 and 5022.

Cold concurrent role startup serializes runtime-table creation with the source schema advisory lock. A PostgreSQL18.6 test reproduced the previous `pg_type_typname_nsp_index` / SQLSTATE `23505` failure before the fix. Failed startup now records the exited role and process status immediately; the cutover ZIP includes bounded role/launcher logs captured before cleanup. Local settings and keys are excluded.

The existing 99 tests passed independently against PostgreSQL18.6 and actual ingestion/analysis/web processes. The final regression set contains 131 tests. GitHub Actions also exercise real Chromium and native Windows PowerShell parsing. Owner-server joint throughput, reboot, eight-hour stability, representative history and labeled precision/recall require the corresponding server receipts and are not accepted from development tests.

PR44's earlier owner trial processed three fresh ES windows in about 22 seconds each for extraction/storage only. That fresh-schema prototype result is not the capacity of this full product. Its original evidence is retained in [the prototype guide](compact_behavior/README_FA.md).

Legacy application code remains in `p24_foundation/`, `review_ui/`, `viewer_performance/` and `AnomalyDetection/`. Only operational stop/restore helpers are reused during Windows cutover; compact extraction and AD do not consume their raw tables or models. Private settings and operational bundles are not included in Git.

```text
python -B -m unittest -v tests.test_compact_extract tests.test_compact_features_v2 tests.test_compact_ad tests.test_compact_trial tests.test_compact_operations
```

Native PostgreSQL tests additionally require `P24_DELTA_PG_HOST`, `P24_DELTA_PG_PORT`, `P24_DELTA_PG_USER` and authentication; run `tests.test_compact_pg`, `tests.test_compact_product_pg` and `tests.test_compact_product_runtime`. See the runbook for owner-server installation and observation.

Meaningful behavior uses the existing reviewed service-role catalog: business and user-management API requests appear by default. Support/system APIs are metadata-only auxiliary observations, excluded from AD; unknown routes remain explicitly unclassified. The UI offers separate all-API and unknown views. Internal/provider/SQL rows sharing RequestID do not become extra actions.

Large scrubbed values are replaced by exact feature snapshots, byte length and a content hash; values up to 16KiB remain available. Target/numeric snapshots have separate 128KiB storage limits and explicit component invalidity. Requests retain a 20MiB state cap and the full input window a 128MiB cap. The input checkpoint is preserved. Model-1 references are not used by model 2: bounded reanalysis rebuilds recent references from compact facts and keeps previous findings/feedback as history. A deterministic input-limit failure ends the installation observation promptly with a receipt.

Owner trial 130645 confirmed the three roles started, but request_state_bytes_limit blocked every new publication, so installation rolled back; it established no joint capacity. The same 400k-character regression now retains 1,209 bytes with identical eligible target/numeric/shape features. All four available captures (349,910 source records) passed offline extraction; that is correctness evidence, not Windows server throughput or labelled anomaly accuracy.
