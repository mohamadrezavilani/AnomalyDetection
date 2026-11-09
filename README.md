# Pishkhan24 Behavior Viewer — Observed Flow and Payments

Current Viewer fix: catalog startup UPDATE uses unique staged action primary keys, writes only changed roles, and preserves selected services behind InvoiceRegister. Native owner snapshot located the startup writer-lock wait; 414 offline checks and the retained 574-record payment replay pass. Native speed remains NOT_RUN; one normal publication is the remaining owner check. See `validation/catalog_startup_fix.json` and `VIEWER_README_FA.md`.

This is the integrated continuation of the supplied M1 snapshot, version `p24-viewer-online-1`.
It displays the latest meaningful execution per Session and continuously imports closed five-minute Elasticsearch windows into the isolated Viewer database.

**Start with [the Persian run guide](VIEWER_README_FA.md).** The current scope and remaining owner-environment gate are in [the roadmap](Pishkhan24_Project_Roadmap.md).

The online path is:

`PIT/search_after capture → strict complete-window proof → retained raw evidence → affected RequestIDs/payment dependencies → request/action/contract/semantic/session-head projections → one atomic publication and checkpoint`.

Runtime dependencies are unchanged. Use the existing Python 3.12 environment and preserve the existing private keys, Viewer database and local configuration. No Core, operational database, original Collector or Anomaly engine is changed. Legacy foundation/detector modules remain as supplied and are not started by the Viewer.

Current owner workflow: close both existing Worker and Web consoles, extract this archive into the same project, run `Start_Viewer.cmd`, and refresh the same request page. All proven fee, bill, basket and payment-result steps now appear in one observed timeline. Inquiry results and per-PaymentKey reports are summarized separately. Readable UI times are Tehran; raw evidence and UTC API fields stay original. Normal launches explicitly select recent startup, with an append-only gap receipt; `-ResumeCheckpoint` remains the explicit continuity mode. One exact unreviewed catalog proposal, UserWidgetsSetDefault, changes to support/unknown with source evidence; operator reviews remain authoritative. Use the bounded read-only report below to diagnose the owner's request and actual worker state. No schema migration, full-history rebuild or long pilot is required.

```powershell
.\Start_Viewer.cmd
python .\tools\inspect_viewer_request.py --request-id 0546b72b-b601-48cf-b4b7-3f7850a30e67
```

Run the pilot to completion before starting the permanent live worker. The web server and live worker use separate terminals. `serve` does not start collection.

For a slow PostgreSQL `FETCH`, stop the worker and run `python tools/diagnose_viewer_fetch.py --config viewer_config.local.py --out validation/viewer_sql_fetch.json` before repeating the full pilot. This bounded reader comparison changes only connection-local temporary tables, runs its data reads in read-only transactions and never ingests, rebuilds projections or advances checkpoints. Incremental contract reading now materializes scoped metadata and retrieves at most 400 exact primary-key payload pairs per batch. The probe and pilot expose separate lookup/fetch/processing timings; the probe alone does not qualify online capacity.

PostgreSQL ingestion reads origin/version evidence in batches of 500, uses COPY into bounded temporary staging tables, and merges within the existing publication transaction. Contract reconstruction uses a named server cursor with bounded batches. Semantic bootstrap reads requests and previous anchors once through a server cursor and refreshes session heads once at the end. Incremental reconciliation also refreshes each affected session in one final set. The pilot prints its worker PID, phase, available row counts, elapsed time and a 15-second heartbeat. A wall-clock watchdog cancels active SQL and stops CPU processing at its next progress check; individual pilot SQL statements have a five-minute timeout. Only publication and the durable checkpoint indicate success. Historical bootstrap remains a one-time full reconciliation.

`validation/final_acceptance.json` states exactly what ran. Archived-source replay and a PGlite SQL check are not native Windows/PostgreSQL/Elasticsearch operational acceptance. `validation/live_acceptance.json` is produced by the owner-environment pilot and is not included in the installation archive. Real payment-correlation UI acceptance is still pending; Anomaly consumption remains outside this release.

For a new code change, the focused regression command is `python tools/run_viewer_tests.py`. The legacy `tools/run_tests.py` covers a different foundation scope; it is not the Viewer release gate.
