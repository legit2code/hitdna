# Fail-Closed Cross-Repository Push Prevention & Identity Governance

**Standard ID**: SEC-GOV-REPO-PREFLIGHT-01  
**Incident Reference**: INCIDENT-REPO-MISROUTE-20261027-01  
**Status**: ACTIVE / ENFORCED  
**Release Freeze**: `releaseFreeze = true` (Active Across Both Projects)  

---

## 1. Executive Summary & Purpose

Following the verified repository misrouting incident where CAIM changes were inadvertently pushed to the HitDNA repository, this standard establishes **fail-closed, multi-layer verification** to permanently prevent any code, commits, tags, releases, or GitHub workflows from crossing project boundaries.

CAIM and HitDNA are strictly independent software projects with separate governance, architectures, threat models, and repository destinations:

| Project | Canonical GitHub Destination | Package Manifest Identity | Primary Domain |
| :--- | :--- | :--- | :--- |
| **CAIM** | `https://github.com/legit2code/caim` | `@caim/platform` (`caim-monorepo`) | Enterprise AI Agent Security Platform |
| **HitDNA** | `https://github.com/legit2code/hitdna` | `hit-dna-music-intelligence` | Music Intelligence Platform |

---

## 2. Multi-Layer Fail-Closed Protection Architecture

Push prevention is enforced through six distinct, deterministic layers. No single layer is trusted in isolation:

```
                  Developer Action / CI Automation
                                 │
                                 ▼
   Layer 1: Workspace Manifest & Foreign Source Contamination Check
                                 │
                                 ▼
   Layer 2: Local Pre-Push Git Hook (.git/hooks/pre-push)
                                 │
                                 ▼
   Layer 3: Destination URL & Refspec Resolution (Explicit URLs & Remotes)
                                 │
                                 ▼
   Layer 4: Branch Policy & Release Freeze Verification (releaseFreeze = true)
                                 │
                                 ▼
   Layer 5: GitHub API Live Repository & Token Scope Verification
                                 │
                                 ▼
   Layer 6: GitHub Actions Workflow Identity Assertion (Step 1 Fail-Closed)
                                 │
                                 ▼
                      [ Git Write Permitted ]
```

---

## 3. Explicit Typed Failure Codes

The preflight guard returns strictly typed failure codes. Silent fallbacks, default-allow logic, or automatic downgrades are strictly forbidden.

### 1. `REPOSITORY_IDENTITY_MISMATCH`
* **Trigger Conditions**:
  - The push destination remote URL points to the wrong repository (e.g. CAIM workspace configured with `legit2code/hitdna`, or HitDNA configured with `legit2code/caim`).
  - An explicit CLI argument targets the wrong repository (e.g. `git push https://github.com/legit2code/hitdna.git main` executed inside CAIM).
  - A renamed remote (e.g. `upstream`, `backup`, `mirror`) points to an unauthorized or mismatched target.
  - The local `package.json` manifest name does not match the expected project identity.
* **Resolution**:
  1. Inspect local remote configuration: `git remote -v`
  2. Reset remote to canonical repository:
     - For CAIM: `git remote set-url origin https://github.com/legit2code/caim.git`
     - For HitDNA: `git remote set-url origin https://github.com/legit2code/hitdna.git`
  3. Verify workspace root `package.json`.

### 2. `REPOSITORY_ACCESS_BLOCKED`
* **Trigger Conditions**:
  - The remote repository does not exist on GitHub (HTTP 404).
  - GitHub authentication token is missing, expired, or invalid (HTTP 401/403).
  - Authenticated token lacks write/push permissions to the target repository.
  - Token scopes lack the mandatory `repo` scope.
* **Resolution**:
  1. Verify token validity: `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/legit2code/<repo>`
  2. Confirm token has push permissions: `permissions.push === true`.

### 3. `PROJECT_SOURCE_CONTAMINATION`
* **Trigger Conditions**:
  - Foreign project files, directories, or artifacts are detected in the active workspace.
  - In CAIM: presence of `hit-dna-music-intelligence.zip`, `src/composer/`, `src/analytics/cohort-service.ts`, `contracts/hit-dna`.
  - In HitDNA: presence of `workers/static-analysis/`, `packages/caim/`, `supabase/tenancy-manifest.json`, `packages/auth/src/service-account.ts`.
* **Resolution**:
  1. Remove all foreign project files immediately.
  2. Never copy files between CAIM and HitDNA workspaces. Use independent, dedicated directories.

### 4. `WORKFLOW_PERMISSION_DENIED`
* **Trigger Conditions**:
  - A GitHub Actions workflow runs inside a repository whose `GITHUB_REPOSITORY` does not match the workflow's intended destination.
  - Release automation is attempted without explicit authorization tokens.
* **Resolution**:
  - Ensure workflows from CAIM are never committed to or triggered in HitDNA, and vice versa.

### 5. `BRANCH_POLICY_BLOCKED`
* **Trigger Conditions**:
  - Direct push to protected branches (`main`, `master`) is attempted without an approved pull request.
  - Direct write to protected branch attempted while `releaseFreeze = true`.
  - Destination branch name violates project branch naming conventions.
* **Resolution**:
  1. Create a dedicated feature or recovery branch: `git checkout -b feat/your-feature`
  2. Push the branch and open a GitHub Pull Request.

### 6. `PUSH_DENIED`
* **Trigger Conditions**:
  - Umbrella denial emitted when preflight checks fail.
  - Release automation push attempted while `releaseFreeze = true`.
* **Resolution**:
  - Inspect the specific failure reasons listed in the preflight output banner.

---

## 4. Developer Standard Operating Procedures

### A. Configuring Safe Git Remotes (Zero Credentials in Config)
Credentials must **never** be embedded into Git remote URLs.

**Forbidden (Insecure):**
```bash
# NEVER store tokens in remote URLs
git remote set-url origin https://ghp_SECRET_TOKEN@github.com/legit2code/caim.git
```

**Required (Secure):**
```bash
# Clean canonical URL
git remote set-url origin https://github.com/legit2code/caim.git

# Provide credentials via environment or credential helper
export GITHUB_TOKEN="ghp_your_scoped_token"
```

### B. Installing and Verifying Pre-Push Hook
Ensure `.git/hooks/pre-push` is installed and executable:

```bash
# In CAIM:
cat << 'EOF' > .git/hooks/pre-push
#!/usr/bin/env bash
set -e
npx tsx scripts/verify-repo-identity.ts "$1" "$2"
EOF
chmod +x .git/hooks/pre-push

# In HitDNA:
cat << 'EOF' > .git/hooks/pre-push
#!/usr/bin/env bash
set -e
npx tsx scripts/verify-hitdna-identity.ts "$1" "$2"
EOF
chmod +x .git/hooks/pre-push
```

### C. Running Preflight Checks Manually
Developers can run preflight verification at any time:

```bash
# In CAIM:
npx tsx scripts/verify-repo-identity.ts

# In HitDNA:
npx tsx scripts/verify-hitdna-identity.ts
```

### D. Running Regression Test Suite
Verify that all 10 push-prevention scenarios pass:

```bash
# In CAIM (Vitest):
npx vitest run tests/repo-identity-guard.test.ts

# In HitDNA (Node Test):
npm test
```

---

## 5. CI Workflow Identity Governance

Every write-capable GitHub workflow must enforce Step 0 identity assertion:

```yaml
- name: 0. Fail-Closed Repository Identity Assertion
  run: |
    if [ "$GITHUB_REPOSITORY" != "legit2code/caim" ]; then
      echo "::error::REPOSITORY_IDENTITY_MISMATCH: Workflow intended exclusively for legit2code/caim cannot run on $GITHUB_REPOSITORY."
      exit 1
    fi
```

HitDNA green runs **never** certify CAIM releases, and CAIM workflows **never** execute on HitDNA.

---

## 6. Release Freeze Status

Across both projects:
```json
{
  "releaseFreeze": true,
  "governance": "ACTIVE",
  "independentWorkspacesEnforced": true,
  "crossRepoPushProtection": "VERIFIED"
}
```
Direct production release publishing remains frozen until independent release certification completes for each project.
