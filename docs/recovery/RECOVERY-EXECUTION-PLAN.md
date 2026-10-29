# CAIM / HitDNA Enterprise Recovery Execution Plan

**Incident ID**: `INCIDENT-REPO-MISROUTE-20261027-01`  
**Execution Phase**: `P0-01 — Final Controlled Preparation`  
**Auditor**: Principal Git Forensics Engineer & Enterprise Source-Control Auditor  
**Date**: `2026-10-27`  
**Status**: `releaseFreeze = true` (Active and Enforced)

---

## 1. Executive Summary

This plan provides a non-destructive, audited path to establish **CAIM** in its own GitHub repository (`legit2code/caim`) and restore **HitDNA** (`legit2code/hitdna`) to its authentic music intelligence baseline.

All operations are designed to:
- Never overwrite published Git history.
- Never force-push (`--force`).
- Never lose authentic HitDNA or CAIM source code.
- Prevent future cross-project repository misrouting through permanent fail-closed preflights.

---

## 2. Operation A: CAIM Repository Establishment (`legit2code/caim`)

### Phase A.1 — Remote Repository Provisioning (Requires User Action/Approval)
1. User creates private GitHub repository:
   - **Owner**: `legit2code`
   - **Repository Name**: `caim`
   - **Visibility**: `Private`
   - **Initialize with README**: No (empty repository)

### Phase A.2 — Local CAIM Initialization & Preflight
In the verified CAIM workspace:
```bash
# 1. Update remote to point strictly to the verified CAIM target
git remote set-url origin https://github.com/legit2code/caim.git

# 2. Execute fail-closed repository preflight
npx tsx scripts/verify-repo-identity.ts
# Must return: [Repo Preflight] Verified: Target matches legit2code/caim:main
```

### Phase A.3 — Push Pristine CAIM Baseline
```bash
# Push verified CAIM tree to the new repository
git push -u origin main
```

---

## 3. Operation B: HitDNA Baseline Restoration (`legit2code/hitdna`)

### Phase B.1 — Non-Destructive Branch Creation
In a HitDNA working directory targeting `legit2code/hitdna`:
```bash
# Checkout new recovery branch from current HEAD
git checkout -b recovery/restore-hitdna-baseline
```

### Phase B.2 — Apply Verified File Restorations
1. Remove the 1,052 misrouted CAIM platform files (all `packages/`, `workers/`, `apps/`, `supabase/`).
2. Restore the 107 authentic HitDNA files from `hit-dna-music-intelligence.zip` (verified from commit `f27eef0`).
3. Sanitize test fixture in `src/testing/unit/config.test.ts` (replace `sk-live-` with `sk-test-MOCK-`).
4. Install HitDNA fail-closed guard `scripts/verify-hitdna-identity.ts`.

### Phase B.3 — Commit & Open Review Pull Request
```bash
git add .
git commit -m "refactor(recovery): restore authentic HitDNA music intelligence baseline

- Remove misrouted CAIM platform files and workers
- Restore HitDNA canonical architecture manifest, domain logic, and contracts
- Restore HitDNA CI baseline workflow
- Sanitize test mock tokens to eliminate scanner false positives
- Add fail-closed repository identity guard (scripts/verify-hitdna-identity.ts)"

git push -u origin recovery/restore-hitdna-baseline
# User reviews and merges PR on GitHub: recovery/restore-hitdna-baseline -> main
```

---

## 4. Operation C: Post-Recovery Credential Rotation

Once both repositories are established and verified:
1. Navigate to **GitHub → Settings → Developer Settings → Personal Access Tokens**.
2. Revoke and delete the 5 tokens exposed during incident diagnostics.
3. Generate fresh, isolated tokens scoped exclusively to each specific repository.

---

## 5. Explicit Operations Requiring User Approval

In compliance with P0-01 governance, the following operations are paused awaiting explicit confirmation:

| Operation | Target Resource | Description | Status |
| :--- | :--- | :--- | :--- |
| **Op 1** | `legit2code/caim` | Provision new private GitHub repository | **PENDING USER APPROVAL** |
| **Op 2** | `legit2code/caim` | Configure remote and push CAIM baseline commit | **PENDING USER APPROVAL** |
| **Op 3** | `legit2code/hitdna` | Push branch `recovery/restore-hitdna-baseline` & open PR | **PENDING USER APPROVAL** |
| **Op 4** | GitHub Account | Revoke 5 exposed diagnostic tokens | **PENDING USER ACTION** |
