# Documentation Index

## Developer documentation

- [Developer guide](DEVELOPER_GUIDE.md) — local setup, package ownership, test strategy, runtime and security invariants.
- [Architecture V2 index](architecture/v2/INDEX.md) — authority hierarchy for governed architecture specifications.
- [Implementation status](implementation/STATUS.generated.md) — machine-generated implementation snapshot; regenerate rather than hand-edit.
- [Truth ledger](implementation/TRUTH_LEDGER.md) — evidence-backed audit findings and external infrastructure requirements.
- [Known gaps](implementation/KNOWN_GAPS.md) — pointer to generated status and truth ledger.
- [Pending decisions](implementation/DECISIONS_PENDING.md) — architectural decisions and resolution notes.
- [Security audit policy](security/audit-policy.md) — audit durability, integrity, and retention requirements.

## Database and certification

- [Supabase/database architecture](../supabase/README.md)
- [Migration sequence](../supabase/migrations/README.md)
- `certification/` — provider and release evidence receipts.

## Reading status correctly

Generated status and certification files are snapshots. Check their timestamps, Git SHA, environment, external-service connectivity, and the truth ledger before using them to make release or production-readiness claims. Architecture specifications describe governed design; verify runtime wiring and deployment evidence separately.
