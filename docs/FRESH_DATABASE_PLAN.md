# Fresh database and refactor operating decision

## Decision

The user permits the old pipeline to remain stopped while we refactor. Availability of the old application is no longer a development constraint. Use a **new PostgreSQL database**, regenerate derived data from retained source logs, and begin operational integration with one day's evidence. Add more history gradually after correctness and capacity checks.

Keep the old database as the preservation source until its unique evidence and user-authored state have been reconciled. Wiping it now offers no implementation benefit. We do not need the old pipeline running to build or test the replacement.

## Sequence

1. Leave existing workers stopped if desired. Record their current versions/configuration. Do not start a second collector implicitly.
2. Before any eventual destructive reset, take a full database backup and separately preserve retained JSON/gzip, Parquet and original documentation, classifications, labels, feedback, reports and current Persian templates. Verify restore into a separate database; merely listing a backup is not a restore test. This batch does not implement operator-state migration, so the old copy remains the source of truth for it.
3. Create the disposable `p24_design_batch2a` database for this component and run the commands in README. The old application database is not initialized or upgraded by this package. Keep test and persistent example namespaces distinct.
4. Complete the remaining foundation gates after bounded Batches 2A–2F: actual producer coverage, complete identity/workflow evidence, authentication/preservation, production-sized reconciliation and serving integration. Then implement reviewed detector/investigation workflows. Select one complete day with actual source manifests, including before/after boundary support. A calendar-day truncation must not discard earlier/later lines belonging to selected RequestIDs.
5. Replay the day in chronological source/receipt order where known. State separately when receipt timing is synthetic or unavailable. Preserve all raw sources; derive new features/reference statistics. Do not call insufficient-history detectors ready.
6. Import/reconcile operator state through an audited crosswalk, preserving old IDs/URLs/report provenance. Keep historical reports marked with their original evidence/version; do not silently reinterpret them as regenerated reports.
7. Expand retained history incrementally, benchmark with representative high-fanout traffic and realistic enabled stages, then qualify Windows/PostgreSQL 17, recovery, permissions and full workflows. One day's data is a bootstrap scope, not proof of detector calibration.
8. Review a concrete integration release and migration plan before replacing the application. No zero-downtime procedure is required, but ownership, backup/restore and reversible data reconciliation still are.

## Reversibility

The new database/configuration/keys/vault are independent. Keep them together for a reproducible replay. The current package does not modify the existing primary database or application startup. If abandoned, stop using the isolated component; there is no down-migration against the primary system. Any later deletion is a separate reviewed disposition after preservation verification, not a prerequisite for this refactor.

## Security/retention boundary

There is no bulk raw evidence UI or decryption CLI. Batch 2G adds signed, namespace-bound permission checks and append-only audit records to the bounded run/publication/request/Session/candidate/evidence read interfaces. The component verifies an externally issued credential but does not authenticate a person, issue credentials, provide PostgreSQL row-level security, or implement an independent/WORM audit sink. The low-level Vault API remains a development boundary available to code holding its key/config; no sensitive-archive read route is exposed. Restrict config/key/vault/token files using reviewed Windows ACLs before local use; Windows ACL qualification is still open. Backup encryption keys separately and securely; losing them makes encrypted evidence unavailable. Do not send keys, passwords, Session tokens or raw credential payloads with test results.

Batch 2G introduces append-only source-evidence holds. They are permanent in this component because there is no release workflow. Held sources cannot pass retention approval, and physical disposition execution is disabled for all objects. No retention duration, automatic deletion, authenticated hold release or key rotation is enabled. Ciphertext orphan objects can remain after rolled-back intake; cleanup requires a later reference-aware retention process. Exact source bytes can be recovered only with the matching namespace, snapshot scope and keys; `raw_object`/snapshot metadata carries their reference.
