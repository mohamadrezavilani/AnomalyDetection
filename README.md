# Pishkhan24 AnomalyDetection

The active project is an independent **UserID-based rebuild**. The existing
Compact product remains the legacy presentation version; its code, models,
data and operational runbook are retained. No automatic migration or production
activation is introduced by the architecture package.

Start with the [current roadmap](Pishkhan24_Project_Roadmap.md) and the
[shared master plan](docs/userid/MASTER_PLAN_FA.md). The owner assigned WP00
architecture and integration first. WP01-WP06 are separate work packages.

| Read | Purpose |
|---|---|
| [Architecture audit](docs/userid/ARCHITECTURE_FA.md) | Existing dependencies, new module boundaries and lifecycle |
| [Data contracts](docs/userid/DATA_CONTRACT_FA.md) | UserID meaning, precision, versioning and integration DTOs |
| [Coordination](docs/userid/COORDINATION_FA.md) | Ownership, decisions, integration order and handoff |
| [JSON schema](contracts/userid/v1/schema.json) | Normalized boundary structure |
| [Synthetic examples](contracts/userid/v1/examples.json) | Shared fixtures without private captures |
| [Legacy Compact runbook](compact_product/README_FA.md) | Existing installation and its historical behavior |

The new web will use port **5022** and an independent database. The old web
keeps its current presentation port. Stopping its writers, making archive
presentation independent of freshness, and deploying either installation are
WP05 work, not effects of this commit.

Contract conformance checks:

```text
python -m pip install jsonschema==4.25.1
python -B -m unittest -v tests.test_userid_contracts
python -B -m contracts.userid.validate
```

The validator performs no network or database initialization. The new source,
database, detector, UI and runtime implementations are not installed by it.
The existing Compact manifest is checked separately with
`python -B -m compact_product version`.
