/**
 * Fail-Closed Repository Identity Preflight for HitDNA Music Intelligence
 * Prevents cross-project repository misrouting incidents (e.g. HitDNA pushed to CAIM or vice-versa).
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import dotenv from 'dotenv';

dotenv.config({ override: true });

export interface HitdnaRepoIdentityOptions {
  expectedOwner?: string;
  expectedRepo?: string;
  expectedBranch?: string;
  remoteName?: string;
  gitRemoteUrl?: string;
  token?: string;
  skipApiCheck?: boolean;
}

export interface HitdnaRepoIdentityResult {
  allowed: boolean;
  code: 'OK' | 'REPOSITORY_IDENTITY_MISMATCH' | 'PUSH_DENIED' | 'ACCESS_BLOCKED';
  reasons: string[];
  details: {
    expected: { owner: string; repo: string; branch: string };
    actual?: { owner?: string; repo?: string; branch?: string; remoteUrl?: string };
  };
}

export async function verifyHitdnaRepositoryIdentity(options: HitdnaRepoIdentityOptions = {}): Promise<HitdnaRepoIdentityResult> {
  const expectedOwner = options.expectedOwner || process.env.EXPECTED_REPO_OWNER || 'legit2code';
  const expectedRepo = options.expectedRepo || process.env.EXPECTED_REPO_NAME || 'hitdna';
  const expectedBranch = options.expectedBranch !== undefined ? options.expectedBranch : (process.env.EXPECTED_BRANCH || 'main');
  const remoteName = options.remoteName || 'origin';
  const reasons: string[] = [];

  // 1. Workspace Identity Check: Verify package.json contains HitDNA signature
  const pkgPath = path.resolve(process.cwd(), 'package.json');
  if (!fs.existsSync(pkgPath)) {
    reasons.push('WORKSPACE_ERROR: package.json not found in current directory.');
  } else {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.name !== 'hit-dna-music-intelligence') {
        reasons.push(`WORKSPACE_IDENTITY_MISMATCH: Workspace package name is '${pkg.name}', expected 'hit-dna-music-intelligence'. Refusing cross-project write.`);
      }
    } catch (e: any) {
      reasons.push(`WORKSPACE_ERROR: Could not parse package.json: ${e.message}`);
    }
  }

  // 2. Local Git Remote Inspection
  let remoteUrl = options.gitRemoteUrl;
  if (!remoteUrl) {
    try {
      remoteUrl = execSync(`git remote get-url ${remoteName}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
    } catch {
      reasons.push(`GIT_REMOTE_ERROR: Could not read URL for remote '${remoteName}'.`);
    }
  }

  let actualOwner = 'UNKNOWN';
  let actualRepo = 'UNKNOWN';

  if (remoteUrl) {
    const match = remoteUrl.match(/github\.com[:/]([a-zA-Z0-9_\-]+)\/([a-zA-Z0-9_\-]+)(?:\.git)?$/);
    if (match) {
      actualOwner = match[1];
      actualRepo = match[2].replace(/\.git$/, '');
    } else {
      reasons.push(`REMOTE_PARSE_ERROR: Cannot parse GitHub owner/repo from remote URL: '${remoteUrl.replace(/:[^:@]+@/, ':***@')}'.`);
    }

    if (actualOwner.toLowerCase() !== expectedOwner.toLowerCase()) {
      reasons.push(`REPOSITORY_OWNER_MISMATCH: Remote owner is '${actualOwner}', expected '${expectedOwner}'.`);
    }

    if (actualRepo.toLowerCase() !== expectedRepo.toLowerCase()) {
      reasons.push(`REPOSITORY_NAME_MISMATCH: Remote target is '${actualRepo}', expected '${expectedRepo}'. Refusing cross-project write.`);
    }
  }

  // 3. Local Branch Verification
  let currentBranch = 'UNKNOWN';
  try {
    currentBranch = execSync('git branch --show-current', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
    if (currentBranch && expectedBranch && currentBranch !== expectedBranch) {
      reasons.push(`BRANCH_MISMATCH: Current branch is '${currentBranch}', expected '${expectedBranch}'.`);
    }
  } catch {
    // In detached HEAD or non-git context
  }

  // 4. Remote API Verification (if token provided and not explicitly skipped)
  const token = options.token || process.env.GITHUB_TOKEN;
  if (!options.skipApiCheck && token && actualOwner !== 'UNKNOWN' && actualRepo !== 'UNKNOWN' && reasons.length === 0) {
    try {
      const authHeader = token.startsWith('ghp_') ? `token ${token}` : `Bearer ${token}`;
      const res = await fetch(`https://api.github.com/repos/${actualOwner}/${actualRepo}`, {
        headers: {
          'Authorization': authHeader,
          'User-Agent': 'hitdna-repo-identity-preflight',
        },
      });

      if (res.status === 404) {
        reasons.push(`ACCESS_BLOCKED: Remote repository 'https://github.com/${actualOwner}/${actualRepo}' does not exist on GitHub (HTTP 404).`);
      } else if (!res.ok) {
        reasons.push(`ACCESS_BLOCKED: Remote repository check failed with HTTP ${res.status}.`);
      } else {
        const repoData: any = await res.json();
        if (repoData.name?.toLowerCase() !== expectedRepo.toLowerCase()) {
          reasons.push(`API_IDENTITY_MISMATCH: GitHub API reported repository name '${repoData.name}', expected '${expectedRepo}'.`);
        }
      }
    } catch (apiErr: any) {
      reasons.push(`API_CHECK_FAILED: Could not reach GitHub API: ${apiErr.message}`);
    }
  }

  const allowed = reasons.length === 0;
  const code = allowed ? 'OK' : reasons.some(r => r.includes('ACCESS_BLOCKED')) ? 'ACCESS_BLOCKED' : 'REPOSITORY_IDENTITY_MISMATCH';

  return {
    allowed,
    code,
    reasons,
    details: {
      expected: { owner: expectedOwner, repo: expectedRepo, branch: expectedBranch },
      actual: { owner: actualOwner, repo: actualRepo, branch: currentBranch, remoteUrl: remoteUrl ? remoteUrl.replace(/:[^:@]+@/, ':***@') : undefined },
    },
  };
}

// CLI entrypoint
const isMain = process.argv[1] && (process.argv[1].endsWith('verify-hitdna-identity.ts') || process.argv[1].endsWith('verify-hitdna-identity.js'));
if (isMain) {
  verifyHitdnaRepositoryIdentity()
    .then((result) => {
      if (!result.allowed) {
        console.error('================================================================================');
        console.error('     FAIL-CLOSED REPOSITORY PREFLIGHT: HITDNA PUSH DENIED');
        console.error('================================================================================');
        console.error(`Status Code: ${result.code}`);
        for (const r of result.reasons) {
          console.error(`  - ${r}`);
        }
        console.error('Expected Target:', JSON.stringify(result.details.expected));
        console.error('Actual Target:  ', JSON.stringify(result.details.actual));
        console.error('================================================================================');
        process.exit(1);
      }
      console.log(`[HitDNA Repo Preflight] Verified: Target matches ${result.details.expected.owner}/${result.details.expected.repo}:${result.details.expected.branch}`);
      process.exit(0);
    })
    .catch((err) => {
      console.error('Fatal preflight error:', err);
      process.exit(1);
    });
}
