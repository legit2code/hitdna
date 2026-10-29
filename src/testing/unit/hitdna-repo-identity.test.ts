import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { verifyHitdnaRepositoryIdentity } from '../../../scripts/verify-hitdna-identity.js';

describe('P0-04: HitDNA Cross-Repository Push Prevention & Identity Guard Suite', () => {
  // Scenario 1: Valid CAIM push target passes
  it('Scenario 1: allows legitimate CAIM push target when evaluated in CAIM mode', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'CAIM',
      expectedOwner: 'legit2code',
      expectedRepo: 'caim',
      gitRemoteUrl: 'https://github.com/legit2code/caim.git',
      skipApiCheck: true,
      manifestOverride: { name: '@caim/platform' },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, true);
    assert.equal(result.code, 'OK');
    assert.equal(result.reasons.length, 0);
  });

  // Scenario 2: Valid HitDNA push target passes
  it('Scenario 2: allows legitimate HitDNA push target to legit2code/hitdna', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, true);
    assert.equal(result.code, 'OK');
    assert.equal(result.reasons.length, 0);
  });

  // Scenario 3: CAIM pushing to HitDNA is rejected
  it('Scenario 3: strictly blocks CAIM project from pushing to legit2code/hitdna', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'CAIM',
      expectedOwner: 'legit2code',
      expectedRepo: 'caim',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: '@caim/platform' },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_NAME_MISMATCH')));
    assert.equal(result.details.actual?.repo, 'hitdna');
  });

  // Scenario 4: HitDNA pushing to CAIM is rejected
  it('Scenario 4: strictly blocks HitDNA project from pushing to legit2code/caim', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/caim.git',
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_NAME_MISMATCH')));
    assert.equal(result.details.actual?.repo, 'caim');
  });

  // Scenario 5: Mismatched workspace manifest is rejected
  it('Scenario 5: strictly blocks push when workspace package manifest is mismatched', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: '@caim/platform' }, // Mismatched CAIM manifest in HitDNA
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('WORKSPACE_IDENTITY_MISMATCH')));
  });

  // Scenario 6: Renamed remote pointing to wrong repo is rejected
  it('Scenario 6: strictly blocks push when a renamed remote (upstream) points to wrong repo', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/caim.git',
      pushArgs: ['upstream', 'main'],
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_NAME_MISMATCH')));
  });

  // Scenario 7: Explicit git push URL pointing to wrong repo is rejected
  it('Scenario 7: strictly blocks explicit git push URL pointing to wrong repo', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      pushArgs: ['https://github.com/legit2code/caim.git', 'main'],
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_NAME_MISMATCH')));
    assert.equal(result.details.actual?.repo, 'caim');
  });

  // Scenario 8: Missing or mismatched GitHub token scope is rejected
  it('Scenario 8: strictly blocks push when token scope lacks required repo write permissions', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      token: 'ghp_invalid_token_sample',
      tokenScope: 'read:user,gist',
      mockApiResponse: {
        status: 200,
        body: { permissions: { push: false } },
        scopes: 'read:user,gist',
      },
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_ACCESS_BLOCKED');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_ACCESS_BLOCKED')));
  });

  // Scenario 9: Branch policy violation is rejected
  it('Scenario 9: strictly blocks direct push to protected branch under active release freeze', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      targetBranch: 'main',
      enforceBranchPolicy: true,
      releaseFreeze: true,
      isReleaseAutomation: true,
      releaseAuthorized: false,
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'BRANCH_POLICY_BLOCKED');
    assert.ok(result.reasons.some(r => r.includes('BRANCH_POLICY_BLOCKED')));
  });

  // Scenario 10: Incomplete authorization stops release automation
  it('Scenario 10: stops automated release execution when release authorization is missing or frozen', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      targetBranch: 'release/v1.0.0',
      isReleaseAutomation: true,
      releaseFreeze: true,
      releaseAuthorized: false,
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.ok(['PUSH_DENIED', 'WORKFLOW_PERMISSION_DENIED'].includes(result.code));
    assert.ok(result.reasons.some(r => r.includes('RELEASE_FROZEN') || r.includes('Release freeze')));
  });

  // Additional Scenario: Cross-project source contamination
  it('detects foreign project source contamination and fails closed', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      contaminationCheck: true,
      contaminationFiles: ['workers/static-analysis', 'supabase/tenancy-manifest.json'],
      workspaceRoot: '/app/applet', // /app/applet contains CAIM files
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'PROJECT_SOURCE_CONTAMINATION');
    assert.ok(result.reasons.some(r => r.includes('PROJECT_SOURCE_CONTAMINATION')));
    assert.ok(result.details.contaminationDetected && result.details.contaminationDetected.length > 0);
  });

  // Additional Scenario: GitHub Actions CI workflow cross-run denial
  it('strictly rejects workflow execution when running in mismatched repository in CI', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      projectName: 'HitDNA',
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
      manifestOverride: { name: 'hit-dna-music-intelligence' },
      isCiEnv: true,
      githubRepositoryEnv: 'legit2code/caim', // Running on CAIM!
      contaminationCheck: false,
    });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'WORKFLOW_PERMISSION_DENIED');
    assert.ok(result.reasons.some(r => r.includes('WORKFLOW_PERMISSION_DENIED')));
  });
});
