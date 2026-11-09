# Recorded acquisition contract — Batch 2H

Contract: `p24-scroll-capture.1`. Implementation: `p24_foundation/acquisition.py` and `intake.py`. This is an isolated intake contract, not a replacement collector or a claim that supplied files are authenticated Elasticsearch responses.

## Evidence and authority

Three independent questions must remain visible:

| Question | Recorded result | Meaning |
|---|---|---|
| Did each selected scroll attempt have a consistent page traversal? | `query_traversal_complete` | The captured transcript passes page, cursor, timeout, shard, origin, time and total checks. This is a consistency assessment of supplied evidence. |
| Is the retained request compatible with the declared unfiltered time window and index scope? | `window_scope_eligible`, `scope_issues` | Request body and declared bounds match the supported shape. Filters, unverified search options and unresolved index aliases remain explicit. |
| Is all evidence for that event window permanently known? | `source_window_complete=false`, `source_finality=not_established` | Not established by a scroll, a local file, a count or a capture clock. |

All current packets have `source_claim_state=unverified_local_capture`. A caller can forge a transcript; checksums bind its exact bytes, not its authenticity. The local intake clock remains the knowledge/receipt boundary. Captured timestamps are retained as claims and cannot backdate eligibility.

The official Elasticsearch documentation states that a scroll reflects the index view at its initial search; later indexing is visible only in a later search. It also documents empty hits as the exhaustion signal and use of the latest scroll ID. A returned cursor may remain unchanged. Independently started slices have independent views; they are never described as one point-in-time snapshot here.

Primary references reviewed October 20, 2026:

- [Paginate search results: scroll, state and termination](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/paginate-search-results)
- [Scroll API response and request contract](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-scroll)

These references explain recorded scroll semantics. Selecting PIT/search_after or changing the actual collector is separate integration work.

## Packet structure

`fixtures/acquisition/complete_scroll.synthetic.json` is a complete, entirely synthetic example. Each packet includes:

| Location | Required content |
|---|---|
| `acquisition` | Contract version; offset-bearing start/end; claimed capture start/end; index pattern; expected slice count; maximum attempt budget; declared query intent |
| `acquisition.query` | `scope` (`window_only` or `filtered`), `time_field`, `range_mode`, explicit `level_filter` |
| `slices[]` | Unique slice ID in `[0, expected_slices)` and ordered attempts |
| `attempts[]` | Contiguous attempt number starting at one, retained initial request, pages, optional safe `failure_kind` |
| `initial_request` | Exact index selector, scroll duration and decoded search body; authentication/transport headers belong outside this contract |
| `pages[]` | Zero-based ordinal, request cursor (null on first page), claimed receipt time, exact decoded Elasticsearch response |

Supported unfiltered search shape matches the retained collector: `query.bool.filter` with one `@timestamp` range containing exactly `gte` and `lt`; `_source: true`; `sort: ["_doc"]`; positive size at most 10,000; matching optional `slice.id/max`. Offset-equivalent bound strings compare by exact instant. A level filter or other filter disqualifies window scope even if traversal completes. Additional search options outside the allowlist, unresolved aliases/remote selectors and mismatched bounds/indexes stay qualified. The full request is archived; public metadata contains only its digest and diagnostic codes.

Only one selected attempt per slice supplies rows: **the latest recorded attempt**. Starting a new scroll does not continue an earlier view. A failed latest attempt does not fall back silently to a previous success. Earlier attempts, including their rows and cursors, remain in the encrypted original. The safe `p24-capture-manifest.1` now records every attempt and page, including initial-request/response digests, row counts, exact claimed page-receipt strings, shard/timeout/termination/total fields, selection state and first selected row offsets. Cursor values are represented only by SHA-256 digests. Earlier attempts retain their own metadata but do not contribute rows to the selected source. To use an earlier attempt deliberately, create a separately identified evidence selection; this API does not invent that decision.

Recognized failure categories are `none`, `transport_timeout`, `http_error`, `cancelled`, and `decode_error`. They are local claims, not raw exception messages or authenticated provider outcomes.

## Traversal rules and bounds

- Each selected attempt must retain its initial request, contiguous page ordinals and a cursor chain using the most recent nonempty response's scroll ID. Repeating the same valid cursor is allowed.
- Every selected page must explicitly report `timed_out=false`, valid nonzero shard total, all shards successful and zero failed. `terminated_early=true` disqualifies traversal. Missing signals remain incomplete.
- A terminal empty page is required. Exact hit totals alone do not establish exhaustion. Pages after termination disqualify the transcript.
- Integer/`eq` totals are exact within that scroll; inconsistent exact totals or mismatch against observed distinct origins disqualify traversal. `gte` remains a lower bound; it is never rewritten to exact. Omitted totals remain unknown. A bound exceeding observed origins is inconsistent.
- Duplicate origins remain separate row memberships; neither duplicates nor conflicting versions are overwritten. They disqualify complete traversal and pass to the existing reconstruction conflict rules. Missing origins/timestamps and out-of-window events also remain explicit.
- Event times compare as integer nanoseconds. The declared source interval is half open; its boundaries must be microsecond representable. A final nanosecond before the end is inside; the exact end is outside.
- Capture receipt order is checked within claimed capture bounds. It remains distinct from source event time and actual local receipt.
- Input and expanded gzip bytes are each limited to 64 MiB. All attempts together are limited to 100,000 hit rows, 2,048 pages, 32 slices and three attempts per slice. Oversized/structurally invalid data is rejected with a safe error; it is never truncated into a complete result. Duplicate JSON object keys are rejected.

Partial but structurally valid transcripts are ingested with their available selected rows and diagnostic flags. A malformed packet rejected before intake is not an archived snapshot. The caller retains the original for correction; no network retry or source deletion occurs.

## Legacy collector dumps and compression

Legacy `{window_start, window_end, index_pattern, count, complete, logs}` files are accepted, including gzip by magic bytes. `complete: true` and matching `count` are preserved as legacy claims; absent page/shard/query evidence means `query_traversal_complete=false` and `source_window_complete=false`. A count mismatch is diagnostic; available rows stay usable.

The inspected collector flattened each hit into its `_source` fields and wrote a reserved `_source_id=index:id`. The adapter recovers `_index` and `_id` only for a single separator, a supported non-remote index name and a nonempty bounded ID without whitespace/control characters. Multiple separators or unknown formats remain originless. No IP, Session, RequestID or content similarity is substituted as event identity. When recovery is unambiguous, overlap against the original Elasticsearch hit deduplicates by the same origin. Original flat bytes remain encrypted and intact. Earlier versions discarded by the old collector's dictionary overwrite cannot be recovered from a later dump.

The raw object records `json` or `json_gzip`; digest and byte count refer to exact supplied bytes, including gzip headers. Decompression is bounded. Re-encoding the same logical data creates another immutable source snapshot; it does not mutate a prior one.

## Persistence, provenance and revisions

The additive `0006_acquisition.sql` migration adds `foundation_acquisition_assessment`, one row per namespaced source snapshot. It binds assessment version, source SHA-256, claim state, traversal flag and safe JSON. A database trigger checks the source digest; checks enforce explicit false window finality and required typed flags; update/delete are rejected. This raised the isolated schema to 85 tables at Batch 2E. Earlier migrations remain unchanged.

Each selected page records its slice, attempt, zero-based selected row start/count, response digest, claimed receipt time, total/relation and terminal signal. Joining that map to immutable `foundation_row_membership` traces selected rows back to the exact encrypted capture. Responses and raw cursors remain in the original; they are omitted from public assessment/evidence output. Schema ownership is not RBAC or authentication; a privileged owner is not defended against deliberate fabrication by these consistency constraints.

Batch 2H adds `foundation_source_manifest` and `foundation_source_receipt`. The manifest binds a bounded safe source description to the exact source digest; a legacy file is explicitly `legacy_unassessed`. Every local ingest call gets an immutable receipt, including a repeated ingest of identical bytes (`reused_identical`). A receipt records the locally accepted timestamp basis, byte/row counts and declared source interval. It does not elevate a caller-supplied capture clock or producer claim to authority. A restart-safe, keyset-paged backfill fills these records for snapshots created by earlier isolated releases.

An observed publication pins the source manifest digest and receipt count/first receipt visible at its `knowledge_at` bound. Later receipts can be reflected in a newly prepared publication; an older publication's manifest, request heads and reads remain unchanged. Explicit source-correction links now carry their revision ID, reason, time and operator-declared/unverified status into the publication manifest. Changed bytes create a new `intake_revision`; neither a count nor a later arrival silently replaces another source. A new projection names its selected snapshots and causal cutoffs. Original runs remain sealed; independently retained support is not erased. This still does not establish producer authority, permanent window finality, or automated acquisition/replay.

## Collector audit and integration boundary

Read-only baseline: `primary-pg.3.8`, `elastic_log_fetcher.py`, SHA-256 `96837ac60ca87a2545eeffea244695d7020ab93bbab0b2b65fa6fb4c79fced61`.

| Baseline area | Observed behavior and implication |
|---|---|
| `_scan_slice`, lines 159–188 | Half-open query; checks timeout/failed shards; drains until empty; uses latest available cursor; dictionary keys overwrite repeated `_index:_id` rows. |
| `fetch_chunk`, lines 190–199 | Slices start independent searches, with separate initial index views. |
| `save_dump`, lines 201–218 | Retains source interval, pattern, count, `complete` flag and flattened logs; page/query/attempt/shard provenance is absent. |
| Live scheduling, lines 255–297 | Latest window plus bounded old-gap/replay work; contiguous cursor is separate. The default 15-minute replay horizon does not establish a maximum possible indexing delay. |

No inspected collector code was changed. Its existing files are not claimed to meet the new recorded-capture contract. No real page transcript was supplied; contract faults are synthetic tests and existing real-chain replay remains a separate check.

Before operational acquisition can be qualified, implement and review a producer adapter with authenticated source/cluster identity, durable page/capture publication, protected receipt/revision provenance, late-arrival policy, cancellation/restart behavior and bounded polling. Validate on the target environment with actual transcripts and realistic volume. A finite replay horizon must report its coverage limit; it must never certify permanent event-window finality.

## Inspection and next batch

The standalone inspector is optional and has no database or network dependency:

```powershell
.\.venv\Scripts\python.exe .\tools\inspect_acquisition.py --input .\fixtures\acquisition\complete_scroll.synthetic.json
```

The existing isolated `ingest` command also supports these formats; its explicit interval must match the declared interval. No command is required from the user for this checkpoint.

Batch 2H is an additive design component, not a collector or production-app update. Offline intake and SQL syntax checks pass in this workspace; native PostgreSQL migration/backfill, correction and publication integration tests still require a disposable PostgreSQL server and remain unverified in this release environment. The full acceptance gate therefore remains open. When available, the integrated run must include late receipts, restart/backfill, correction/removal, partial arrival and full-versus-incremental oracles. Producer integration, authentication/retention, target Windows qualification and workflow reconciliation remain separate open gates.

## Finite collector integration (M1-B)

Implementation: `p24_foundation/collector_pipeline.py` and `tools/collector_pipeline.py`. This is a finite, explicit path alongside the existing application. The target's collector, coordinator and entry point are not patched. `catalogs/collector_target_sha256.json` pins the eight source hashes supplied by the user; the three previously differing files were uploaded and verified exactly. This is a local source baseline, not an authenticated producer identity or a review of every target file.

Run from the consolidated project directory using its Python environment:

```powershell
python tools/collector_pipeline.py inspect --target-root "C:\path\to\existing\Pishkhan24_PostgreSQL"
```

`inspect` reads hashes only: no target imports, database or network. `capture` is an explicit ES read using the target collector's existing transport/settings. It imports the exact verified collector/config bytes in this dedicated process and never calls their production `main`, supervisor or ingestion pipeline. One unfiltered, single-slice, five-minute request is retained, including its initial query, actual decoded responses, request/response cursors and terminal empty page. No origin is silently discarded. The existing assessor determines traversal/scope eligibility; producer authority, finality and complete traffic remain unverified.

Only when a target capture is explicitly requested, substitute its actual path and a closed historical window:

```powershell
python tools/collector_pipeline.py capture --target-root "C:\path\to\existing\Pishkhan24_PostgreSQL" --start "2026-10-20T07:25:00Z" --end "2026-10-20T07:30:00Z" --output private/capture-attempt-1.json --max-runtime-seconds 120
```

The raw output contains source payloads/cursors and must stay local and private. It is never uploaded by the tool. Output replacement is refused. Partial attempts are retained with a fixed failure code; ineligible captures return exit code 2 and cannot be published through this path. Public output contains only counts, digest and diagnostic codes. The one-response JSON decode uses the existing target transport; its memory consumption and server/version compatibility still need target qualification. POSIX capture creation uses mode 0600; Windows ACL qualification is open.

For a reviewed initialized disposable `p24_design_*` database, select a dedicated namespace for this stream in the existing private config. Do not substitute the application's `pishkhan24_shadow` database or bypass guards. Prepare a local JSON plan; paths are relative to the plan file, and `sha256` is the capture command's returned digest:

```json
{
  "version": "p24-collector-import.1",
  "stream": "main-es",
  "index_pattern": "logs-*",
  "expected_generation": 0,
  "event_cutoff": "2026-10-20T07:30:00Z",
  "captures": [
    {"path": "capture-attempt-1.json", "sha256": "<returned SHA256>"}
  ]
}
```

```powershell
python tools/collector_pipeline.py publish --config db_config.local.py --plan private/import-plan.json
```

Generate a plan from only named captures (the output is created exclusively and existing files are preserved):

```powershell
python tools/collector_pipeline.py plan --stream main-es --index-pattern "logs-*" --expected-generation 0 --event-cutoff "2026-10-20T07:30:00Z" --captures private/capture-attempt-1.json --output private/import-plan.json
```

For a declared correction, pass `--replacements private/replacements.json`. It must be a JSON array with exactly one matching entry for each corrected five-minute window, using `{ "window_start": "...", "window_end": "...", "snapshot_id": "...", "intake_revision": 1 }`. The publisher independently checks that snapshot and revision against the current selected source. The plan command reads no database or network and leaves capture bytes unchanged.

This command never initializes a database automatically. If the approved disposable database has not been initialized, use the existing explicit `python -m p24_foundation --config db_config.local.py init` procedure first. Keys/config remain private; no new environment-variable setup is required for foundation persistence.

Every plan is bounded to 128 captures, 100,000 input rows, 64 MiB of original bytes and 64 MiB of decoded row content in aggregate. All input bytes, scopes and digests are checked before persistence. The selected current vector is retained; there is no mtime-based authority, directory polling, silent eviction or automatic source-head promotion. Existing publication limits still apply to the total retained vector, including correction ancestry. The current pointer must belong to the same stream/index scope. Namespace locking, expected generation, receipts, explicit correction links and the publication update share one database transaction. A failed update is designed to leave the prior pointer and SQL ledger unchanged; its native rollback case remains unexecuted here. Append-only vault objects created before failure may remain as unreferenced evidence.

For a changed capture of an already selected window, add `"replaces": {"snapshot_id": "<previous imported ID>", "intake_revision": 1}` to that capture's plan entry. Use the exact returned revision, not a guessed value. A replacement is a local declared selection, not verified producer finality. Identical bytes reuse the snapshot and add a receipt. Old publications, evidence, decisions and source snapshots remain untouched. Intake time is the actual local clock; capture timestamps are claims and cannot backdate knowledge. Publication mode is `historical_revised`; it is not an online-original replay.

No workflow/identity meanings are inferred from legacy flags. A publication from this path reports workflow data unavailable until a reviewed adapter provides an exactly pinned workflow projection; old workflow pins are not silently carried onto new evidence. Supervised scheduling, authenticated source/issuer authority, vector scaling, native/real replay, target Windows acceptance and sustained operation remain open. Six native cases are registered in `tools/run_tests.py`; offline success is not a substitute for their execution.

**Plan command complete:** it reads and hashes only the explicitly named captures, validates the exact import format through `load_plan`, rejects partial/out-of-cutoff/duplicate-window input and duplicate or unmatched replacement hints, and refuses to replace an existing output. Capture count is checked before opening inputs; aggregate limits stop further reads. Temporary validation plans are created exclusively with POSIX mode 0600 and removed on validation failure. Nineteen offline collector tests pass. Windows ACL qualification remains open.

### Operating decisions reviewed October 22, 2026

| Decision | Supported boundary and consequence |
|---|---|
| Source authority | The eight code hashes select the local transport baseline. A retained eligible transcript supports observed rows and successful traversal of that recorded query. It does not authenticate Elasticsearch, establish a stable index snapshot, prove all platform traffic was returned, or prove that later records cannot arrive. Observed replay may proceed with these limitations visible. |
| Late evidence and corrections | No timeout or elapsed number of windows establishes finality. Use explicit corrected captures and current snapshot/revision declarations. Continue stitching RequestID and authoritative SessionID across windows; retain old publications. Missing windows and ineligible captures remain gaps; a later success cannot erase the record of a failed attempt. |
| Workflow adapter | No supported production workflow adapter is established by the available source files. Keep workflow state unavailable. A future adapter must bind authenticated issuer decisions, exact selected source versions, reviewed service/contract versions, subject scope and sequence semantics. HTTP acknowledgements, log flags and Session/IP coincidence cannot supply these meanings. |
| Finite operation | One named stream/index per namespace, explicit ordered plans, and the existing generation fence. Retained source/correction ancestry, 100,000-event/head limits and 128-source bounds remain hard stops. They are not a rolling retention policy or a daily capacity commitment. A supervisor must stop on failure/uncertainty and preserve earlier successful publications. |

### Finite supervision and reconciliation

`p24_foundation/replay.py` implements the reviewed finite supervisor, exposed through the existing tool:

```powershell
python tools/collector_pipeline.py replay --config db_config.local.py --plans private/plan-1.json private/plan-2.json --max-runtime-seconds 300 --output private/replay-report.json
```

Plan order is exactly the argument order. Each plan carries its own expected generation; the supervisor never changes it. Accept 1–128 plans and a total runtime budget of 1–3600 seconds. The tool creates a complete private report exclusively before starting a child. Each `publish` runs in a separate Python process using an argument array and `shell=False`. No collector is started. A private in-flight report is written atomically before each launch; completed steps retain publication IDs and generations. Source paths, payloads, credentials and child errors do not enter the report. Child stdout is file-backed, with at most 64 KiB read for result parsing; stderr is discarded. POSIX temporary/report modes are 0600; target Windows ACL and hard-link support require qualification. An unsupported atomic-create filesystem causes refusal before publication.

A failure, interruption, timeout, missing/malformed/oversized result or report-write failure stops the sequence. A timed-out or interrupted child is killed and reaped. The budget prevents further publication work; process cleanup and report I/O may outlast it. No retry or automatic resume occurs. Every started publication without a confirmed success is `outcome_unknown`, because it may have committed before its response was lost. Earlier successful steps remain recorded. If reporting fails after publication starts, the last in-flight report remains a reconciliation warning. Exit code 0 means the full sequence completed; other terminal statuses return 2. A forcibly killed supervisor can leave `status: running`; its last in-flight step must also be reconciled.

Use the exact plan from an uncertain step to inspect commit evidence:

```powershell
python tools/collector_pipeline.py reconcile --config db_config.local.py --plan private/plan-2.json
```

This reads the commit ledger at `expected_generation + 1` in a repeatable-read, read-only transaction, even if a later publication is current. It checks whether the planned capture bytes are selected at that commit and whether its event cutoff matches. It creates no namespace, reads no private keys/Vault objects, writes no database records and exposes no source payloads. `planned_content_observed` identifies matching selected content; it does not identify which process published it, verify replacement ancestry, or prove that no other source changes occurred. `no_commit_observed_at_read_time` is a point-in-time observation, not permission to retry. Reconcile all uncertain work and review the current generation before preparing another explicit plan; the command never authorizes or performs retries. Exit code 0 means inspection ran, not that the plan committed: inspect the returned `assessment`.

Thirteen offline supervisor/reconciliation tests cover real child termination, interruptions, ordered success, failure and unknown outcomes, bounded result parsing, report preservation/privacy, CLI failure handling and read-only historical inspection. Six native collector cases are prepared, including real child publication and stale-generation rejection. They remain unexecuted here. Native rollback-before-commit, timeout/commit ambiguity, real-source replay, continuous ES scheduling, durable supervised ownership, scalable publication storage and sustained target workload acceptance remain open. No broad full-service catalog is required for observed-row replay; unsupported workflow claims remain unavailable. M1-B remains open.

## Integrated scheduled runner

`tools/run_pipeline.py start` now composes the verified collector transport, digest-pinned import plan, guarded publication, causal Session/service detector and per-window Persian HTML/JSON reports. It is explicitly started in the foreground. Existing production entry points and databases are not modified. This is an experimental design-database runner, not a qualified production service.

Each window is five minutes, aligned to UTC. The runner waits until its end plus the explicit lag, runs one bounded child, and processes windows sequentially. It stores private captures, plans, publication identities, reports and a durable result in `window_NNNN/`. The first window reports insufficient history without inventing a reference. Later windows use earlier confirmed publications from that exact run. `--persist-candidates` explicitly enables the already reviewed experimental incident adapter; it does not assign fraud or operator priority. Without that flag, detector reads are read-only.

### Preparation and explicit pilot

Use the existing virtual environment and checked local database config. Native tests used temporary keys; this actual runner needs the configured real private key file. Create keys only if they do not already exist, and keep them with the matching database/evidence vault:

```powershell
New-Item -ItemType Directory -Force .\private | Out-Null
if (-not (Test-Path .\private\evidence.keys.json)) {
    python -m p24_foundation generate-keys --path private/evidence.keys.json
}
python -m p24_foundation --config db_config.local.py init
```

Those example key paths must match `KEYS_PATH` in the local config. A different configured path must be used consistently; never regenerate or replace existing keys for an initialized namespace.

After current native acceptance, use an explicit original project path and its actual Elasticsearch index pattern. `--target-root` names the original folder containing the eight files in `catalogs/collector_target_sha256.json`; it does not name the redesigned foundation folder. Capture reuses that original project's local ES configuration and does not ask for credentials in chat. The following is a syntax example; replace all placeholders before running:

```powershell
python tools/run_pipeline.py start --config db_config.local.py --target-root "C:\PATH\TO\ORIGINAL_PROJECT" --state-dir private/pipeline-pilot --start "YYYY-MM-DDTHH:MM:00Z" --windows 2 --stream pilot --index-pattern "ACTUAL_INDEX_PATTERN" --rank-cutoff "1/20" --lag-seconds 60 --window-timeout-seconds 180
python tools/run_pipeline.py status --state-dir private/pipeline-pilot
```

`--start` must be an exact five-minute UTC boundary. Choose historical windows known to exist for a finite pilot. The rank is an explicit descriptive candidate policy, not a calibrated false-positive rate. Two windows exercise the path but cannot establish enough personal history for this rank policy.

Rerunning the identical start command resumes only confirmed progress. An OS ownership lock prevents two supervisors from sharing the same state directory. Independently launched publishers in other directories still use the existing database generation fence; this is not a global production worker lease. Changing the run specification is rejected. Ctrl+C during waiting is safe; interruption/timeout after a child starts leaves an in-flight window and blocks automatic replay. Captures and old reports are never removed.

### Recovery and limits

If `state.json` reports `requires_reconciliation`, do not delete state or blindly rerun publication. Inspect that window's `phase.json`, `publication.json` if present, and its plan through the existing read-only command:

```powershell
python tools/collector_pipeline.py reconcile --config db_config.local.py --plan private/pipeline-pilot/window_0001/plan.json
```

A committed publication can exist even when scoring/report writing failed. Reconciliation does not prove which process committed content and never authorizes automatic replay. An operator must resolve that outcome before advancing; automated recovery of an uncertain write is intentionally unavailable.

A run contains 1–128 windows, retains the complete selected source vector, and remains subject to the existing 128-source and aggregate 100,000-record/request bounds. It stops on capacity or validation errors rather than evicting evidence. Restarting with a different directory does not bypass database capacity. This is not sufficient evidence for unlimited 24-hour operation at the stated workload. A longer historical reference store, measured capacity, reviewed late/correction scheduling, authenticated source/workflow authority and target recovery qualification remain necessary. Corrections still use the explicit reviewed replacement plan with the scheduler paused; there is no invented source-finality claim.

Offline crash/scheduling checks cover ownership, ordered progress, restart, mismatch refusal, durable confirmation, timeout/interrupt reaping and unknown-outcome blocking. Three new native cases cover actual two-window publication/reporting, explicit incident abstention, and postcommit report failure. All three pass in the supplied 400-test target run. The remaining Windows check concerns a repaired offline test command length; no production workload qualification is inferred.

### Older original project compatibility

The real pilot folder is `C:\Users\Administrator\PycharmProjects\TestProject\log_managment_fixed`. Its collector matches the reviewed older archive (`e5b18e7b…`); the supplied local settings fingerprint is pinned separately. Capture now verifies only the collector and settings it executes. The old eight-file `inspect` remains a full-target baseline diagnostic; missing legacy migration files no longer block this transport-only path. Legacy ingestion, writers, scheduler main and application entry points are not loaded. Settings are trusted local Python, not an independently reviewed producer; their console output is suppressed. Credentials remain local. Changed collector/settings bytes still fail closed. `inspect-transport` verifies/loads this pair without network/DB access.

The integrated runner's `--index-pattern` is now optional: when omitted it uses the verified transport's configured index, keeping the capture/plan scope consistent. The user's 11 repaired Windows pipeline checks pass. Four compatibility checks pass locally; no SQL/schema/persistence behavior changed in this adapter update. Use the existing native composition evidence, and proceed to a two-window real-source pilot rather than repeating the full native suite.
