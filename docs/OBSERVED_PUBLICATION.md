# Observed-evidence publication — Batch 2F

Implementation: `p24_foundation/publication.py`, additive migration `0007_observed_publication.sql`. Contract version: `p24-observed-publication.2f.1`.

## Semantics and ownership

A publication is an immutable, explicitly scoped view of request reconstructions. It names the source vector, source-revision choices, event cutoff, knowledge bound, mode, parser/resolver/privacy/catalog versions and registration-context horizon. It references sealed reconstruction runs; unchanged requests may keep references to earlier runs.

The publication's time/source scope and a reused run's original computation scope are distinct. Read APIs return both publication ID and originating run ID. A reused head is valid because its relevant input evidence and reconstruction policy remain unchanged, not because its old global cutoff has been rewritten.

The current-publication pointer is the only mutable serving selector. Readers pin one publication ID for every page, request, operation and Session view. A newer current pointer does not change an existing pin or its signed cursors. Preparing a view does not publish it. A prepared sealed view can be inspected by its explicit ID as a local development preview.

All publications have `evidence_scope=observed_only`, `source_window_complete=false`, `producer_authority=unverified_local_capture` and `authoritative_source_heads_published=false`. No `source_head` or legacy serving head is modified. Publication is a consistency/availability decision, not proof of complete traffic, an authenticated producer, a person, account ownership or detector readiness.

## Incremental reconciliation

1. Validate a caller-selected source vector and expected current generation. Freeze explicit replacement choices and source metadata. Reject sources outside the namespace or beyond the declared knowledge bound.
2. Compare the old and target effective source sets. Added/removed sources seed affected origin identities. An event-cutoff advance also seeds origins crossing the exact nanosecond boundary; a knowledge advance seeds newly receipt-eligible versions. Policy changes force a full policy rebuild. Time regression is refused on this current-view channel; historical projections remain available separately.
3. Close the origin/RequestID graph across the old and target sources. Every variant of an origin is considered, including variants with another or missing RequestID. Expand affected requests back to all of their origins until stable. This prevents a conflicting version from disappearing through a RequestID filter.
4. Reconstruct only affected RequestIDs that have support in the target vector, using all of their relevant target-source origins and variants. Scoped runs explicitly record their RequestID scope and cannot complete a full-source projection work item.
5. Reuse unaffected request-run references. Remove heads whose support vanished from the selected view, while preserving independent source support and every earlier source/run/publication. A removal is a view tombstone, not evidence deletion.
6. Seal a publication with exact head digest, entry/request counts, coverage and reconciliation statistics. Preparing identical inputs against the same base reuses that prepared publication.

The request reconstruction/scoped outcome algorithms were retained. This batch changes evidence selection scope and serving mechanics, not detector algorithms, severity, business taxonomy authority or score interpretation.

The impact algorithm conservatively rebuilds requests touched by source/provenance changes, including a duplicate origin arriving in another retained source. This preserves accurate evidence provenance even when the summary's HTTP count does not change.

## Storage and publication protocol

| Table | Responsibility |
|---|---|
| `foundation_projection_request_scope` | Immutable RequestID membership for a scoped sealed reconstruction |
| `foundation_observation_publication` | Frozen input/coverage/statistics/head digest, base generation and draft-to-sealed state |
| `foundation_observation_entry` | Request head upserts/removals or a complete head checkpoint; references sealed request projections |
| `foundation_observation_commit` | Append-only published generation and timestamp |
| `foundation_observation_current` | Atomically advanced pointer to the committed current publication |
| `foundation_observation_access` | Append-only publication-scoped read audit with a verified, namespace-keyed opaque principal |

The migration adds six tables for 91 total (72 unchanged base and nineteen foundation). Earlier migrations remain unchanged and checksum-verified.

Normal publications store affected head entries only. Checkpoints store the complete current head map without reconstructing unchanged requests. The default checkpoint interval is 64 overlay generations; a large replacement delta can trigger an earlier checkpoint. Checkpoints bound the read overlay chain; they do not truncate audit history or infer recovery. A tombstone wins over older entries, and a checkpoint ends inheritance from its predecessor. Empty checkpoints correctly represent an explicitly empty view.

Publishing takes a short namespace fence and verifies the exact base publication/generation and head digest. It inserts the committed generation and advances the current pointer in one PostgreSQL transaction. Database guards reject unsealed heads, frozen-entry/header mutation, stale or skipped generations, backward pointer moves and a committed publication that never becomes current in its transaction. Failed publication leaves the previous pointer intact. Re-publishing an already committed ID is idempotent and cannot move current back to it.

Preparation/scoped reconstruction uses the existing namespace write lock for consistent source-resolution choices. Existing immutable namespace contracts now have a read path that avoids that write lock. A new reader can connect and read the old committed publication while a publisher's pointer update is still uncommitted. Production lock contention and throughput require operational measurement. Component permission checks are not human identity federation, PostgreSQL RLS or an independent audit sink.

## Read models and historical evidence

The publisher supports pinned request lists, Session activity, individual requests, request evidence, registration candidates and publication metadata. Each read requires an externally issued signed investigator credential bound to the configured namespace; a denied or allowed attempt receives an append-only decision record, and successful result reads also append an opaque publication access record. Signed cursors bind namespace key, publication, view kind and scope. A cursor from an older publication cannot be silently used against a newer one, even if a request's originating run was reused.

Session pages combine every applicable request head across reused and new runs. They order by exact activity time and RequestID token; ambiguous requests without a known activity time remain reachable in the general request list. Registration context is recomputed from the complete published head set, not only newly reconstructed requests. It remains a candidate association. Truncation limits cause an explicit error rather than a false complete result.

Run-level candidate queries refuse a scoped reconstruction because it lacks the complete context. Use publication-level candidates or a full-source run. Publication-scoped reads append their own audit records; existing request/evidence run audits are preserved.

This batch also corrects a historical evidence-read defect: ambiguous/unavailable rows previously joined every current version of an origin in the namespace. A later unselected source could therefore change an old run's displayed evidence. Both page rows and counts now require membership in that run's immutable source vector and its knowledge mode. Later variants cannot leak into the old view or invalidate its page boundaries. Run summaries and publication status are also gated, so their source references and aggregate counts are not available through unauthenticated inspection commands.

## Bounds and remaining work

- Each selected vector has at most 128 snapshots and 100,000 distinct input versions. A published view has at most 100,000 request heads. These are inherited component bounds, not a production sizing recommendation.
- Impact closure uses at most 200,000 union origins/requests across old and target vectors and 64 expansion steps. Oversized/nonconvergent work fails explicitly; it is never silently skipped or marked complete.
- Signed pages contain at most 100 rows. Overlay depth stays at most 63. Registration-context searches keep the existing bounded horizon and candidate limits.
- Reconciliation still enumerates bounded source membership and the head map. It avoids reconstructing/deserializing unchanged requests and rewriting all head entries each update, but it is not constant-time processing or an all-day capacity result.
- Queue work remains full-source projection work. There is no unattended publication/collector scheduler, Flask serving integration, detector/reference invalidation, automatic history expansion, retention deletion, production RBAC or actor/account lifecycle completion in this batch.
- Windows/PostgreSQL 17, OS ACLs, sustained throughput, real-load lock contention, process/host recovery and complete workflow qualification remain open. The Linux UID/stat test harness does not establish those properties.

Rollback of this isolated checkpoint means stopping its CLI and retaining its database/keys/vault for review. Do not point a pre-2F component at scoped 2F run IDs: older read code does not understand their subset scope. No down-migration or old-database deletion is provided. The existing operational application is independent and untouched.

## Optional development CLI

No user action is required now. These commands are for a separately configured disposable design database and this cumulative package:

```powershell
.\.venv\Scripts\python.exe -m p24_foundation --config .\db_config.local.py prepare-observation --sources <snapshot-id> --cutoff 2026-10-20T07:40:00Z --knowledge-at <actual-knowledge-time> --expected-generation 0 --mode design_fixture
.\.venv\Scripts\python.exe -m p24_foundation --config .\db_config.local.py publish-observation --publication <prepared-id>
.\.venv\Scripts\python.exe -m p24_foundation --config .\db_config.local.py observation
.\.venv\Scripts\python.exe -m p24_foundation --config .\db_config.local.py observed-session --publication <published-id> --session-file .\private\session.txt
```

Use the returned generation as the next preparation's expected generation. `--empty` deliberately selects an empty view; it never deletes source evidence. `design_fixture` is a labeled replay mode, not online receipt history. Operational modes enforce their source/receipt knowledge bounds. Store Session tokens only in the private file, not command history or returned results.

## Session/service volume detector and Persian report

`p24_foundation/behavior.py` provides the first implemented M2 candidate: observed logical-request counts per authoritative Session and opaque route within a five-minute window. SQL/provider/cache observations do not become extra requests. Automatic client calls retain their RequestID units. IP is not part of the behavior identity.

The reference is that same Session/route's earlier **active** five-minute windows. Missing traffic is not zero activity. Unknown/conflicting identity, conflicting client completions and ambiguous event versions do not supply observations. New login Sessions and insufficient history abstain. Reused RequestIDs across reference/target windows make only the affected Session/route ineligible; unrelated groups continue.

The descriptive upper-tail rank is `(1 + earlier counts >= target count) / (1 + number of active reference windows)`. A candidate requires both rank at or below the explicitly supplied rank cutoff and an increase above the personal median. No fixed request-count threshold, fraud verdict, priority promotion or population wealth/location rarity is introduced. For a cutoff of `1/20`, at least 19 active personal reference windows are needed merely to resolve that rank. This is a resolution condition, not an established usefulness threshold. Temporal dependence, selection of active windows, multiple testing and changing logging conditions prevent interpreting the rank as a calibrated false-positive probability. Real usefulness and operational policy acceptance remain open.

The database reader accepts only committed sealed publications, requires an exact event cutoff at each window end, and admits one eligible single-slice collector capture for that window. Reference and target stream/index/contract scopes must match. Overlapping reference windows, future event intervals, references learned after the target publication's knowledge cutoff and excessive inputs are rejected. The mode is `historical_revised`: reference evidence may have arrived after the historical event interval, so this does not reproduce an original online decision. Inputs and counts are pinned by publication IDs, window/knowledge cutoffs, selected request digests and policy digest. The trusted local command reads within one repeatable-read, read-only transaction and never creates namespaces or findings/decisions.

Try the complete report path without PostgreSQL:

```powershell
python tools/detect_behavior.py --demo --format html --output private/behavior-demo.html
```

This clearly labeled synthetic example produces one personal-volume candidate and leaves an actor with ordinarily high activity unflagged. JSON is the default output format. Both formats preserve an existing output; files are private and installed atomically. The HTML view shows up to 100 evaluation rows, with candidate rows first, and labels that limit. JSON retains all bounded evaluations. Raw Session IDs, IPs, routes, messages and payloads are excluded; navigation uses existing keyed request/session identifiers. Persian text reports observed counts and reference support while leaving cause, fraud and priority undetermined.

For native data, create a local reference manifest containing an explicit ordered JSON array of `{ "publication_id": "<committed UUID>", "start": "<offset-bearing time>", "end": "<offset-bearing time>" }`, then run:

```powershell
python tools/detect_behavior.py --config db_config.local.py --target-publication <committed-id> --start <five-minute-start> --end <five-minute-end> --references private/behavior-references.json --rank-cutoff 1/20 --format html --output private/behavior-report.html
```

Use the guarded disposable design database, its matching keys and committed collector publications. No production default cutoff is selected. Review the descriptive rank policy before interpreting candidates. The one prepared `BehaviorPostgresTests` case exercises twenty actual committed capture windows through the reader and Persian scoring path; it has not run here. Fifteen offline cases cover reconstruction, personal references, high normal volume, IP continuity, new Sessions, abstention, causality, overlap, scope eligibility, privacy and report escaping. The retained real Session fixture preserves its 33 evidence rows and 10 logical requests; it provides insufficient personal history for usefulness evaluation.

`catalogs/detector_scope.json` records a targeted interface/scope review and design disposition for all 13 legacy families, grounded in checksummed source from the retained pg_3_8 archive. It also identifies the additional longitudinal helper. These are design dispositions, not empirically accepted keep/retire conclusions. Markov remains a shadow challenger pending comparison with simpler sequence models. Payload/schema integrity and endpoint health retain their own scopes. M2-A and M2-B remain open for reviewed normal/abnormal cases, held-out evaluation, additional justified families and persistent finding/incident integration.

### Explicit candidate persistence and operator incidents

The same detector command can now recompute and persist experimental candidates inside one guarded database transaction. Add `--persist-candidates --expected-generation <current-publication-generation>` to the native command above. The target must be the current committed publication. The default command remains read-only; demo input cannot enable persistence. Namespace locking and the expected publication generation fence cover scoring, findings, request support, incident revisions and their selected evaluations. A stale target, changed baseline selection or failed incident refresh rolls the entire database operation back.

`p24_foundation/behavior_store.py` writes deterministic detector/finding IDs and links every logical target request to its actual pinned projection run. A candidate spanning multiple projection runs creates evidence partitions sharing one evaluation identity, not extra model observations. Normal or abstaining assessments are retained as observations; they create no new incident, but update an existing incident's selection so a previous positive does not remain active. An exact rerun reuses the same findings and incident revision. Historical evaluations cannot be silently reselected by replaying an old report.

Incident evidence includes a digest of the **whole** target Session/route request-head set and explicit reference capture snapshots. New or corrected target requests invalidate all partitions together, including additions outside a partition's original request list. Replaced reference captures also exclude older candidates. The incident revision records an explicit evaluation selection for each target window; changed policy/reference assessments replace that selection without changing historical versions. Unknown bindings abstain. These rules extend only behavior-bound findings; legacy findings keep their existing evidence checks.

Existing incident pages and deterministic Persian briefs now show the observed target/reference counts and candidate explanation. Briefs deduplicate evaluation partitions and show at most three labeled explanation samples. Candidate status does not establish fraud, calibrated detection quality, root cause or priority. Human decisions and manual priority records are not overwritten. A changed evidence revision retains the existing stale-priority semantics.

Native persistence is **implemented but unverified in this environment**. The prepared `BehaviorPostgresTests` case now covers the twenty-window publication path, repeatability, a late target correction, stale-evidence exclusion, mixed projection support where present, an abstaining reassessment, preservation of historical incident versions, rejected historical reselection and rollback after an injected incident failure. Offline binding and brief checks are recorded separately. These prepared cases are not native pass evidence.

A report-file failure can occur after the database transaction committed. Such CLI failures expose `persistence_outcome: requires_reconciliation`; never infer rollback or perform a blind retry from an output-file error. Inspect the current publication and incident state first. Report creation uses the existing private/exclusive filesystem rules; Windows ACL/filesystem and full operational qualification remain open.
