/**
 * Fail-Closed Repository Identity Preflight for HitDNA Music Intelligence
 * P0-04: Permanent Cross-Repository Push Prevention
 * 
 * Enforces strict, multi-layer verification before any Git push or release write:
 * 1. Workspace manifest identity ('hit-dna-music-intelligence')
 * 2. Workspace contamination check (no CAIM or foreign files)
 * 3. Git remote destination resolution (including explicit URLs and renamed remotes)
 * 4. Branch policy enforcement (protected branch guard & release freeze)
 * 5. GitHub API repository existence & token push permission check
 * 6. CI workflow environment & release authorization check
 * 
 * Fail-Closed Typed Error Codes:
 * - REPOSITORY_IDENTITY_MISMATCH
 * - REPOSITORY_ACCESS_BLOCKED
 * - PROJECT_SOURCE_CONTAMINATION
 * - WORKFLOW_PERMISSION_DENIED
 * - BRANCH_POLICY_BLOCKED
 * - PUSH_DENIED
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import dotenv from 'dotenv';

dotenv.config({ override: true });

export type PreflightFailureCode =
  | 'OK'
  | 'REPOSITORY_IDENTITY_MISMATCH'
  | 'REPOSITORY_ACCESS_BLOCKED'
  | 'PROJECT_SOURCE_CONTAMINATION'
  | 'WORKFLOW_PERMISSION_DENIED'
  | 'BRANCH_POLICY_BLOCKED'
  | 'PUSH_DENIED';

export interface HitdnaRepoIdentityOptions {
  projectName?: 'CAIM' | 'HitDNA';
  expectedOwner?: string;
  expectedRepo?: string;
  expectedManifestNames?: string[];
  expectedBranch?: string;
  targetBranch?: string;
  remoteName?: string;
  gitRemoteUrl?: string;
  pushArgs?: string[];
  token?: string;
  tokenScope?: string;
  tokenPermissions?: { push?: boolean; pull?: boolean; admin?: boolean };
  skipApiCheck?: boolean;
  mockApiResponse?: { status: number; body?: any; scopes?: string };
  workspaceRoot?: string;
  manifestOverride?: { name?: string; [key: string]: any };
  contaminationCheck?: boolean;
  contaminationFiles?: string[];
  enforceBranchPolicy?: boolean;
  isReleaseAutomation?: boolean;
  releaseFreeze?: boolean;
  releaseAuthorized?: boolean;
  githubRepositoryEnv?: string;
  isCiEnv?: boolean;
}

export interface HitdnaRepoIdentityResult {
  allowed: boolean;
  code: PreflightFailureCode;
  reasons: string[];
  details: {
    project: string;
    expected: {
      owner: string;
      repo: string;
      branch?: string;
      manifestNames: string[];
    };
    actual?: {
      owner?: string;
      repo?: string;
      branch?: string;
      remoteUrl?: string;
      manifestName?: string;
    };
    contaminationDetected?: string[];
  };
}

// Foreign project contamination markers that must never exist in HitDNA
export const HITDNA_FORBIDDEN_CONTAMINATION = [
  'workers/static-analysis',
  'packages/caim',
  'supabase/tenancy-manifest.json',
  'packages/auth/src/service-account.ts',
  'packages/packaging/src/crypto/canonical-payload.ts',
  'apps/server/routes/agent-lineage.routes.ts',
];

export const CAIM_FORBIDDEN_CONTAMINATION = [
  'hit-dna-music-intelligence.zip',
  'src/composer',
  'src/analytics/cohort-service.ts',
  'contracts/hit-dna',
  'tools/integrity',
];

/**
 * Sanitizes URLs and messages to guarantee zero credential/token logging.
 */
export function sanitizeLogString(str: string): string {
  if (!str) return '';
  return str
    .replace(/https:\/\/[^:@\s]+:[^@\s]+@/g, 'https://***@')
    .replace(/https:\/\/[^:@\s]+@/g, 'https://***@')
    .replace(/ghp_[A-Za-z0-9_]{10,}/g, 'ghp_***')
    .replace(/github_pat_[A-Za-z0-9_]{10,}/g, 'github_pat_***');
}

/**
 * Extracts owner and repository name from any Git remote URL or ref.
 */
export function parseOwnerAndRepo(rawUrl: string): { owner?: string; repo?: string } | null {
  if (!rawUrl) return null;
  const cleanUrl = rawUrl.trim();
  const match = cleanUrl.match(/github\.com[:/]([a-zA-Z0-9_\-]+)\/([a-zA-Z0-9_\-]+?)(?:\.git|\/)?$/);
  if (!match) return null;
  return {
    owner: match[1],
    repo: match[2].replace(/\.git$/, ''),
  };
}

/**
 * Parses push arguments to extract destination remote/URL and target ref/branch.
 */
export function parsePushArguments(
  args: string[] = [],
  workspaceRoot: string = process.cwd()
): { destinationUrl?: string; targetBranch?: string; remoteName?: string } {
  let destinationUrl: string | undefined;
  let targetBranch: string | undefined;
  let remoteName: string | undefined;

  const nonFlags = args.filter(a => !a.startsWith('-'));

  if (nonFlags.length > 0) {
    const firstArg = nonFlags[0];
    if (
      firstArg.startsWith('https://') ||
      firstArg.startsWith('http://') ||
      firstArg.startsWith('git@') ||
      firstArg.startsWith('ssh://')
    ) {
      destinationUrl = firstArg;
    } else {
      remoteName = firstArg;
      try {
        destinationUrl = execSync(`git remote get-url ${remoteName}`, {
          cwd: workspaceRoot,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'ignore'],
        }).trim();
      } catch {
        destinationUrl = undefined;
      }
    }
  }

  if (nonFlags.length > 1) {
    const refspec = nonFlags[1];
    if (refspec.includes(':')) {
      const parts = refspec.split(':');
      targetBranch = parts[1].replace(/^refs\/heads\//, '');
    } else {
      targetBranch = refspec.replace(/^refs\/heads\//, '');
    }
  }

  return { destinationUrl, targetBranch, remoteName };
}

/**
 * Universal repository identity and cross-repo push verification engine for HitDNA.
 */
export async function verifyHitdnaRepositoryIdentity(
  options: HitdnaRepoIdentityOptions = {}
): Promise<HitdnaRepoIdentityResult> {
  const projectName = options.projectName || 'HitDNA';
  const expectedOwner = options.expectedOwner || process.env.EXPECTED_REPO_OWNER || 'legit2code';
  const expectedRepo =
    options.expectedRepo ||
    process.env.EXPECTED_REPO_NAME ||
    (projectName === 'HitDNA' ? 'hitdna' : 'caim');
  const expectedManifestNames =
    options.expectedManifestNames ||
    (projectName === 'HitDNA'
      ? ['hit-dna-music-intelligence']
      : ['@caim/platform', 'caim-monorepo']);
  let workspaceRoot = options.workspaceRoot;
  if (!workspaceRoot) {
    try {
      workspaceRoot = execSync("git rev-parse --show-toplevel", { encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] }).trim();
    } catch {
      workspaceRoot = process.cwd();
    }
  }
  const enforceBranchPolicy = options.enforceBranchPolicy ?? true;
  const releaseFreeze = options.releaseFreeze ?? true;
  const reasons: string[] = [];
  let failureCode: PreflightFailureCode = 'OK';

  // 1. Workspace Manifest Identity Check
  let actualManifestName: string | undefined;
  if (options.manifestOverride) {
    actualManifestName = options.manifestOverride.name;
  } else {
    const pkgPath = path.resolve(workspaceRoot, 'package.json');
    if (!fs.existsSync(pkgPath)) {
      reasons.push('WORKSPACE_ERROR: package.json not found in workspace directory.');
      failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
    } else {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        actualManifestName = pkg.name;
      } catch (err: any) {
        reasons.push(`WORKSPACE_ERROR: Could not parse package.json: ${err.message}`);
        failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
      }
    }
  }

  if (actualManifestName) {
    const matchesExpected = expectedManifestNames.some(
      expected => actualManifestName === expected || (actualManifestName && actualManifestName.startsWith(expected))
    );
    if (!matchesExpected) {
      reasons.push(
        `WORKSPACE_IDENTITY_MISMATCH: Workspace package name is '${actualManifestName}', expected one of [${expectedManifestNames.join(
          ', '
        )}]. Refusing cross-project operation.`
      );
      failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
    }
  }

  // 2. Contamination Check: Verify absence of foreign project artifacts
  const checkContamination = options.contaminationCheck ?? true;
  const contaminationDetected: string[] = [];
  if (checkContamination) {
    const forbiddenMarkers =
      options.contaminationFiles ||
      (projectName === 'HitDNA' ? HITDNA_FORBIDDEN_CONTAMINATION : CAIM_FORBIDDEN_CONTAMINATION);
    for (const marker of forbiddenMarkers) {
      const fullPath = path.resolve(workspaceRoot, marker);
      if (fs.existsSync(fullPath)) {
        contaminationDetected.push(marker);
      }
    }
    if (contaminationDetected.length > 0) {
      reasons.push(
        `PROJECT_SOURCE_CONTAMINATION: Detected ${contaminationDetected.length} foreign artifact(s) from opposite project: [${contaminationDetected.join(
          ', '
        )}].`
      );
      if (failureCode === 'OK') failureCode = 'PROJECT_SOURCE_CONTAMINATION';
    }
  }

  // 3. Resolve Destination URL and Target Branch
  let destinationUrl = options.gitRemoteUrl;
  let remoteName = options.remoteName || 'origin';
  let targetBranch = options.targetBranch;

  if (options.pushArgs && options.pushArgs.length > 0) {
    const parsed = parsePushArguments(options.pushArgs, workspaceRoot);
    if (parsed.destinationUrl) destinationUrl = parsed.destinationUrl;
    if (parsed.remoteName) remoteName = parsed.remoteName;
    if (parsed.targetBranch && !targetBranch) targetBranch = parsed.targetBranch;
  }

  if (!destinationUrl) {
    try {
      destinationUrl = execSync(`git remote get-url ${remoteName}`, {
        cwd: workspaceRoot,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();
    } catch {
      if (!options.gitRemoteUrl) {
        reasons.push(`GIT_REMOTE_ERROR: Could not resolve URL for remote '${remoteName}'.`);
        if (failureCode === 'OK') failureCode = 'PUSH_DENIED';
      }
    }
  }

  let actualOwner = 'UNKNOWN';
  let actualRepo = 'UNKNOWN';

  if (destinationUrl) {
    const parsed = parseOwnerAndRepo(destinationUrl);
    if (parsed) {
      actualOwner = parsed.owner || 'UNKNOWN';
      actualRepo = parsed.repo || 'UNKNOWN';
    } else {
      reasons.push(
        `REMOTE_PARSE_ERROR: Cannot parse GitHub owner/repo from destination URL: '${sanitizeLogString(
          destinationUrl
        )}'.`
      );
      if (failureCode === 'OK') failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
    }

    if (actualOwner.toLowerCase() !== expectedOwner.toLowerCase()) {
      reasons.push(
        `REPOSITORY_OWNER_MISMATCH: Destination owner is '${actualOwner}', expected '${expectedOwner}'.`
      );
      if (failureCode === 'OK') failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
    }

    if (actualRepo.toLowerCase() !== expectedRepo.toLowerCase()) {
      reasons.push(
        `REPOSITORY_NAME_MISMATCH: Destination target is '${actualRepo}', expected '${expectedRepo}'. Refusing cross-project write.`
      );
      if (failureCode === 'OK') failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
    }
  }

  // 4. Branch Verification & Branch Policy Enforcement
  if (!targetBranch) {
    try {
      targetBranch = execSync('git branch --show-current', {
        cwd: workspaceRoot,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();
    } catch {
      targetBranch = undefined;
    }
  }

  if (options.expectedBranch && targetBranch && targetBranch !== options.expectedBranch) {
    reasons.push(`BRANCH_MISMATCH: Current branch is '${targetBranch}', expected '${options.expectedBranch}'.`);
    if (failureCode === 'OK') failureCode = 'BRANCH_POLICY_BLOCKED';
  }

  if (enforceBranchPolicy && targetBranch) {
    const isProtected = ['main', 'master'].includes(targetBranch);
    if (isProtected && releaseFreeze && options.isReleaseAutomation) {
      reasons.push(
        `BRANCH_POLICY_BLOCKED: Direct write to protected branch '${targetBranch}' blocked under active release freeze.`
      );
      if (failureCode === 'OK') failureCode = 'BRANCH_POLICY_BLOCKED';
    }
  }

  // 5. GitHub Actions / CI Environment Verification
  const isCi = options.isCiEnv ?? (process.env.GITHUB_ACTIONS === 'true');
  const ciRepo = options.githubRepositoryEnv || process.env.GITHUB_REPOSITORY;
  if (isCi && ciRepo) {
    const expectedCiRepo = `${expectedOwner}/${expectedRepo}`;
    if (ciRepo.toLowerCase() !== expectedCiRepo.toLowerCase()) {
      reasons.push(
        `WORKFLOW_PERMISSION_DENIED: Workflow running in '${ciRepo}', expected '${expectedCiRepo}'. Cross-project workflow execution is forbidden.`
      );
      if (failureCode === 'OK') failureCode = 'WORKFLOW_PERMISSION_DENIED';
    }
  }

  // 6. Release Automation Authorization Gate
  if (options.isReleaseAutomation) {
    if (releaseFreeze && !options.releaseAuthorized) {
      reasons.push(
        `PUSH_DENIED: Release freeze governor is active (releaseFreeze = true). Automated release writes are strictly blocked.`
      );
      if (failureCode === 'OK') failureCode = 'PUSH_DENIED';
    } else if (!options.releaseAuthorized) {
      reasons.push(
        `WORKFLOW_PERMISSION_DENIED: Incomplete authorization token or signature for automated release.`
      );
      if (failureCode === 'OK') failureCode = 'WORKFLOW_PERMISSION_DENIED';
    }
  }

  // 7. GitHub API Access & Token Scope Verification
  const token = options.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const skipApi = options.skipApiCheck ?? false;

  if (options.mockApiResponse) {
    const mock = options.mockApiResponse;
    if (mock.status === 401 || mock.status === 403) {
      reasons.push(`REPOSITORY_ACCESS_BLOCKED: GitHub authentication failed (HTTP ${mock.status}).`);
      if (failureCode === 'OK') failureCode = 'REPOSITORY_ACCESS_BLOCKED';
    } else if (mock.status === 404) {
      reasons.push(
        `REPOSITORY_ACCESS_BLOCKED: Remote repository 'https://github.com/${expectedOwner}/${expectedRepo}' does not exist or token lacks access (HTTP 404).`
      );
      if (failureCode === 'OK') failureCode = 'REPOSITORY_ACCESS_BLOCKED';
    } else if (mock.status === 200) {
      if (mock.body?.permissions && mock.body.permissions.push === false) {
        reasons.push(
          `REPOSITORY_ACCESS_BLOCKED: Authenticated token lacks push/write permissions to '${expectedOwner}/${expectedRepo}'.`
        );
        if (failureCode === 'OK') failureCode = 'REPOSITORY_ACCESS_BLOCKED';
      }
    }
  } else if (!skipApi && actualOwner !== 'UNKNOWN' && actualRepo !== 'UNKNOWN' && failureCode === 'OK') {
    if (!token) {
      reasons.push('REPOSITORY_ACCESS_BLOCKED: GitHub API access verification requires authentication token.');
      failureCode = 'REPOSITORY_ACCESS_BLOCKED';
    } else {
      try {
        const authHeader = token.startsWith('ghp_') ? `token ${token}` : `Bearer ${token}`;
        const res = await fetch(`https://api.github.com/repos/${actualOwner}/${actualRepo}`, {
          headers: {
            Authorization: authHeader,
            'User-Agent': `${projectName.toLowerCase()}-repo-identity-preflight`,
          },
        });

        if (res.status === 401 || res.status === 403) {
          reasons.push(`REPOSITORY_ACCESS_BLOCKED: GitHub API rejected token (HTTP ${res.status}).`);
          failureCode = 'REPOSITORY_ACCESS_BLOCKED';
        } else if (res.status === 404) {
          reasons.push(
            `REPOSITORY_ACCESS_BLOCKED: Remote repository 'https://github.com/${actualOwner}/${actualRepo}' does not exist or token lacks access (HTTP 404).`
          );
          failureCode = 'REPOSITORY_ACCESS_BLOCKED';
        } else if (!res.ok) {
          reasons.push(`REPOSITORY_ACCESS_BLOCKED: Remote repository check failed with HTTP ${res.status}.`);
          failureCode = 'REPOSITORY_ACCESS_BLOCKED';
        } else {
          const repoData: any = await res.json();
          if (repoData.name?.toLowerCase() !== expectedRepo.toLowerCase()) {
            reasons.push(
              `API_IDENTITY_MISMATCH: GitHub API reported repository name '${repoData.name}', expected '${expectedRepo}'.`
            );
            failureCode = 'REPOSITORY_IDENTITY_MISMATCH';
          } else if (repoData.permissions && repoData.permissions.push === false) {
            reasons.push(
              `REPOSITORY_ACCESS_BLOCKED: GitHub API confirmed token does NOT have write (push) permission to '${actualOwner}/${actualRepo}'.`
            );
            failureCode = 'REPOSITORY_ACCESS_BLOCKED';
          }
        }
      } catch (apiErr: any) {
        reasons.push(`REPOSITORY_ACCESS_BLOCKED: Network error reaching GitHub API: ${apiErr.message}`);
        failureCode = 'REPOSITORY_ACCESS_BLOCKED';
      }
    }
  }

  if (options.tokenScope && !options.tokenScope.includes('repo')) {
    reasons.push(`REPOSITORY_ACCESS_BLOCKED: GitHub token scopes [${options.tokenScope}] lack required 'repo' scope.`);
    if (failureCode === 'OK') failureCode = 'REPOSITORY_ACCESS_BLOCKED';
  }

  const allowed = reasons.length === 0;
  if (!allowed && failureCode === 'OK') {
    failureCode = 'PUSH_DENIED';
  }

  return {
    allowed,
    code: allowed ? 'OK' : failureCode,
    reasons,
    details: {
      project: projectName,
      expected: {
        owner: expectedOwner,
        repo: expectedRepo,
        branch: options.expectedBranch,
        manifestNames: expectedManifestNames,
      },
      actual: {
        owner: actualOwner,
        repo: actualRepo,
        branch: targetBranch,
        remoteUrl: destinationUrl ? sanitizeLogString(destinationUrl) : undefined,
        manifestName: actualManifestName,
      },
      contaminationDetected: contaminationDetected.length > 0 ? contaminationDetected : undefined,
    },
  };
}

// CLI entrypoint
const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('verify-hitdna-identity.ts') ||
    process.argv[1].endsWith('verify-hitdna-identity.js'));

if (isMain) {
  const args = process.argv.slice(2);
  verifyHitdnaRepositoryIdentity({ pushArgs: args })
    .then(result => {
      if (!result.allowed) {
        console.error('================================================================================');
        console.error('     FAIL-CLOSED REPOSITORY PREFLIGHT: PUSH DENIED');
        console.error('================================================================================');
        console.error(`Status Code: ${result.code}`);
        for (const r of result.reasons) {
          console.error(`  - ${sanitizeLogString(r)}`);
        }
        console.error('Expected Target:', JSON.stringify(result.details.expected));
        console.error('Actual Target:  ', JSON.stringify(result.details.actual));
        console.error('================================================================================');
        process.exit(1);
      }
      console.log(
        `[HitDNA Repo Preflight] Verified: Target matches ${result.details.expected.owner}/${result.details.expected.repo}`
      );
      process.exit(0);
    })
    .catch(err => {
      console.error(`[HitDNA Repo Preflight] Unhandled error: ${sanitizeLogString(err.message)}`);
      process.exit(1);
    });
}
