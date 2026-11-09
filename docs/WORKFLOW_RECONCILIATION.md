# Workflow reconciliation contract — 2R kernel / 2S persistence

`reconcile_workflows()` is a bounded pure projection over typed selected facts. Inputs are selected evidence, external-event assertions, delivery observations, workflow states and explicit state contracts. Exact duplicate inputs are idempotent; input order does not affect the projection or its SHA-256.

## Trust and knowledge

The producer/database adapter must authenticate issuers and prove assertion/fact references belong to the cited sealed-run source. The kernel consumes verifier decisions; it does not verify credentials. Arbitrary log text saying `verified` is not authority. No real issuer/state contract is configured in this milestone.

Selected evidence cites a namespace-scoped origin token, immutable version UUID, exact event nanoseconds and receipt time. Event cutoff is exclusive; knowledge cutoff inclusive. Unknown times, future sources, late receipts and conflicting origin versions are excluded explicitly. Missing/ineligible references are counted by observation family. Old returned projections remain unchanged when later evidence is supplied.

## Independent units

| Unit | Identity and treatment |
|---|---|
| Logical external event | Verified issuer + topic + identifier domain + token key version + keyed token. Content equality alone does not create identity. Source fact/assertion references and verified authenticity are required adapter inputs. |
| Content revision | Content SHA-256 + schema version within one logical event. Different revisions conflict; later arrival does not authorize correction. |
| Delivery observation | One selected source version. Contradictory assertions on that source become one conflicting/ambiguous observation. |
| Identified attempt | Verified issuer + attempt domain + keyed attempt token. Several source observations can describe one attempt. Conflicting identifiers abstain. |
| Transport request | Distinct retained keyed RequestID, separate from event and business-success counts. |
| State observation | Accepted source-bound workflow link + reviewed contract version + whole-workflow or subject scope. Subjects remain independent. |

## State rules

Contracts are disabled by default. An enabled contract has a version, authority reference, review state, source roles, state meanings, permitted transitions, terminal states and optional issuer-sequence domain. Partial/unverified evidence, missing source facts, wrong roles and unknown states/contracts abstain.

Consistent observations publish the observed state. Multiple states without a matching authoritative sequence conflict. Every sequenced observation needs the matching domain and nonnegative integer. Sequence ties with different states, unapproved transitions and reversals from terminal states conflict. Timestamps never choose the winner. State outputs cite source-version and state-fact references. An observed terminal state does not prove source finality or successful processing of every subject.

HTTP acknowledgement cannot establish business success. IP/Session coincidence cannot link workflows. PostgreSQL persistence, selected source-fact binding and immutable publication/read integration are implemented in 2S; see historical `docs/MILESTONE_2S.md` inside [the history archive](../archive/project_history.zip). Current completion status is defined by [the roadmap](../Pishkhan24_Project_Roadmap.md). Signature/issuer validation and real-contract qualification remain open. Verified input flags are internal trusted decisions, not provider authentication.
