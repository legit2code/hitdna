import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { verifyHitdnaRepositoryIdentity } from '../../../scripts/verify-hitdna-identity.js';

describe('HitDNA Repository Identity Guard & Isolation Invariant', () => {
  it('strictly blocks push when target points to CAIM instead of HitDNA', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/legit2code/caim.git',
      skipApiCheck: true,
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_NAME_MISMATCH')));
    assert.equal(result.details.actual?.repo, 'caim');
    assert.equal(result.details.expected.repo, 'hitdna');
  });

  it('strictly blocks push when target owner is mismatched', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      gitRemoteUrl: 'https://github.com/unauthorized-org/hitdna.git',
      skipApiCheck: true,
    });

    assert.equal(result.allowed, false);
    assert.equal(result.code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.ok(result.reasons.some(r => r.includes('REPOSITORY_OWNER_MISMATCH')));
  });

  it('allows push when target is legitimately legit2code/hitdna', async () => {
    const result = await verifyHitdnaRepositoryIdentity({
      expectedOwner: 'legit2code',
      expectedRepo: 'hitdna',
      expectedBranch: '',
      gitRemoteUrl: 'https://github.com/legit2code/hitdna.git',
      skipApiCheck: true,
    });

    assert.equal(result.allowed, true);
    assert.equal(result.code, 'OK');
    assert.equal(result.reasons.length, 0);
  });
});
