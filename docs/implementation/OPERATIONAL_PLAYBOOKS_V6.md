# Hit DNA Music Intelligence — Operational Playbooks (v6)

These standard operating procedures govern operational workflows, recovery scenarios, data integrity incidents, and provider onboarding under the v6 Evidence-Enforced Build Law.

---

## 1. New Data Provider Onboarding Procedure v6

P00 + P00A remain in force.
1. Add a provider only through the shared adapter contract and source policy.
2. Start in operational state `NOT_CONFIGURED` or `CONFIGURED_UNVERIFIED`.
3. `AVAILABLE` requires a real executed provider-specific verification result under current config; credentials/name/adapter existence are insufficient.
4. Preserve raw provenance, rate-limit/error/freshness state and licensing/policy metadata.
5. Add negative tests for auth failure, timeout/rate limit, stale prior success and policy-disabled state.
6. Run `npm run integrity:providers` and phase verification.

---

## 2. Integrity Re-Audit Procedure v6

1. Do not add features.
2. Re-run `npm run integrity:all`.
3. Validate every completed post-P00A receipt against the current schema/check matrix/architecture hash.
4. Compare `BUILD_STATE` and coverage claims to executable code and tests.
5. Report every mismatch. Do not automatically repair by weakening checks. Small factual wiring defects may be fixed; architecture/methodology changes require the Architecture Change Guard process.

---

## 3. Failure Recovery Procedure v6

P00 + P00A remain in force.
1. Fix ONLY the failing/current phase.
2. Read its receipt and exact failed checks.
3. Preserve legitimate migrations and data.
4. Fix root cause; never weaken, skip, update golden expectations, or bypass an integrity check merely to obtain PASS.
5. Run the smallest failing tests first, then `npm run phase:verify <PROMPT_ID>`.
6. `BUILD_STATE` may advance only after a new valid PASS receipt.
7. Report `NOT_EXECUTED` checks exactly.

---

## 4. Evidence Receipt Recovery Procedure v6

Use when a phase claims completion but its receipt is missing, malformed or inconsistent.
1. Do not synthesize historical command output.
2. Re-run all currently reproducible phase checks from repository state.
3. Generate a fresh receipt with actual commands and exit codes.
4. Mark historical-only items `NOT_VERIFIABLE` where necessary.
5. Downgrade `BUILD_STATE` if the current repository cannot reproduce PASS.

---

## 5. Data Integrity Incident Procedure v6

Treat suspected fabricated, fixture-contaminated, unsupported, untraceable or wrongly promoted production intelligence as an incident.
1. Stop publication and affected generation paths immediately.
2. Identify exact records, metrics, snapshots, and provider states.
3. Preserve original evidence and audit trail.
4. Quarantine and revoke affected derived publications.
5. Rerun applicable integrity checks.
6. Do not repair truth by inventing replacement facts; recalculate only from authoritative accepted evidence.
7. Produce an incident report with scope, lineage, affected receipts/releases, and validation proving remediation.

---

## 6. Architecture Change Guard Procedure v6

Do NOT change the locked architecture yet.
1. Record the exact blocking implementation fact, affected architecture version/hash, engine/module IDs, data/contracts, integrity checks, compatibility/security impact, and smallest compatible alternative in `docs/implementation/DECISIONS_PENDING.md`.
2. A change that adds/removes/renames canonical domains/engines/modules requires explicit approval, a new architecture version, regenerated manifest/matrices/prompt pack/visual architecture, and updated integrity expectations.
3. Never edit the manifest merely to make `integrity:architecture` pass.

---

## 7. AI Studio Resume Procedure v6

P00 + P00A remain in force.
1. Before coding, read `BUILD_STATE`, the completion ledger, current architecture manifest/hash, `KNOWN_GAPS`, `DECISIONS_PENDING`, and the latest phase receipts.
2. Verify the last completed phase receipt is present, schema-valid, matches architecture 5.0.0/hash (`091dbc8629246eadd10581acbd41285c9b72ee1712bb1cddd0de783ec125d80b`), and has `PASS`.
3. If it is missing/mismatched, do not advance; return `RESUME_BLOCKED_INTEGRITY` with the exact discrepancy.
4. Do not rerun completed phases unless their evidence is invalid.
5. Never reconstruct a missing PASS from memory.
