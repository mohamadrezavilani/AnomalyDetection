# Batch 2G — evidence access and preservation

Release: `p24-foundation.2g.1`. Scope: isolated design component only. This is not an application authentication rollout or approval to modify the existing PostgreSQL application.

## Signed investigation credentials

The component verifies a compact Ed25519-signed credential. It does not issue credentials, authenticate a human, or decide which role an operator should receive. A trusted external issuer must first authenticate the operator and sign the exact role claims. Until that issuer is configured, reads fail closed.

The token is `base64url(canonical-JSON-claims).base64url(signature)`. Claims are exact and include `version=1`, `iss`, `aud`, `namespace`, opaque `subject`, `roles`, integer `iat`, integer `exp`, and UUID `jti`. The verifier checks signature, issuer, audience, namespace, known roles, issue/expiry times, and a maximum eight-hour lifetime. Unknown claim fields are rejected. The configured Ed25519 **public** key is not a secret. This package contains no private production signing key and no token-issuance command.

| Role | Current capability |
|---|---|
| `investigator` | Read one request, bounded request pages, Session activity, registration candidates, and source-backed request evidence |
| `preservation_officer` | Place a source-evidence preservation hold |
| `audit_reviewer` | Reserved for a separately implemented audit reader; it grants no current read route |
| `sensitive_evidence_reader` | Reserved for a separately reviewed raw-archive route; raw payload access is not implemented |

The CLI accepts credentials only from a private token file, never from an argument value. On POSIX, it rejects token files with group/other permission bits. Windows file protection requires reviewed Windows ACLs and has not been qualified. Investigation-read APIs do not accept the former `--operator` string as proof of identity.

Every permitted or denied gated read appends a decision row before the result query. Audit rows store only a namespace-keyed subject token, an HMAC of the credential attempt, and a typed HMAC resource key; they never store the bearer token, RequestID, SessionID, IP, or raw payload. The public CLI returns only `access_denied`; the safe reason category is held in the audit row. The existing run/publication read audit trails also carry the verified opaque subject and `verified_signed_credential` state.

This is a per-application authorization check over a shared database connection. It is not PostgreSQL row-level security, an independent/WORM audit sink, or protection from a database owner or compromised application process. Any future Flask integration must verify the token at the request boundary, use namespace-bound credentials, and preserve audit writes outside rollback-prone business transactions. The example harness tests a synthetic signing key only.

## Payload handling

Original export bytes remain encrypted in the local vault with authenticated encryption and namespace/snapshot-bound associated data. Relational descriptors retain field names, presence/completeness and scoped outcome metadata; individual secret values and arbitrary input/output payloads are not projected into public inspection responses. The evidence page returns source-linked typed descriptors, not raw log messages. Existing ciphertext and source-object rows are immutable in the database.

No raw archive download/view route is exposed by this batch. A future route must require both ordinary investigation access and a specifically approved sensitive-evidence role, display field-level masking by default, audit each revealed object, and apply a documented purpose and time limit. The `sensitive_evidence_reader` role currently authorizes no implemented route.

## Preservation holds and retention boundary

`foundation_evidence_hold` is append-only and references an exact source snapshot, with an optional exact raw object. It stores a controlled reason, a keyed digest of an optional reference, and the verified subject token. `foundation_active_evidence_hold` is a current view; all holds are active because this batch deliberately provides no release action. A hold does not change a source head, projection, finding, or evidence-availability claim.

The database rejects an approved retention disposition when its source is held or its retention policy is not approved. It rejects **all physical `executed` dispositions**, even if an approved retention policy exists. Raw source objects already reject update/delete. No collector export, Parquet, Elasticsearch evidence, operator state, or legacy database is deleted by this package. There is no retention duration, hold-release workflow, archive garbage collector, key rotation, or physical deletion implementation.

Holds are permanent in this batch. Do not place them casually. A later release needs authenticated preservation authority, two-person or equivalent approval, an immutable release event, a complete reference-aware hold check, and a separately approved retention policy before it can be designed.

## Qualification

Tests cover valid/expired/tampered/misbound/overlong credentials, narrow role checks, opaque access audit rows, missing-credential denial, append-only holds, non-disclosing inspection and database rejection of held or executed dispositions. Test signing keys and test roles are synthetic. Production identity federation, operator/role provisioning, Windows ACLs, independent audit retention, privacy/legal review, retention periods and recovery of archived keys remain open under P2-05.
