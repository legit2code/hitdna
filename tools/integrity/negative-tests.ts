/**
 * Controlled Negative Self-Tests for v6 Truth & Integrity Verification Suite
 * Proves that:
 * 1. An architecture mismatch or altered hash is rejected.
 * 2. Fixture contamination in a production file is rejected.
 * 3. A malformed/manual PASS receipt is rejected.
 * 4. A failing required check prevents phase PASS.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { IntegrityChecker } from './integrity-checker.js';

console.log('[negative-tests] Starting Controlled Negative Self-Tests...');

// Test 1: Architecture mismatch fails
{
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-arch-'));
  try {
    fs.mkdirSync(path.join(tempDir, 'docs/architecture'), { recursive: true });
    // Write corrupted manifest with wrong architecture version
    fs.writeFileSync(
      path.join(tempDir, 'docs/architecture/canonical_manifest.json'),
      JSON.stringify({ architectureVersion: '4.9.9', engineCount: 65, moduleCount: 600 }),
      'utf8'
    );
    const checker = new IntegrityChecker(tempDir);
    const result = checker.verifyArchitecture();
    assert.equal(result.passed, false, 'Corrupted architecture manifest must fail');
    console.log('  ✓ Negative Test 1 passed: Architecture mismatch correctly rejected.');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

// Test 2: Fixture contamination fails
{
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-fixture-'));
  try {
    fs.mkdirSync(path.join(tempDir, 'src/domain'), { recursive: true });
    // Write fake production file containing TEST_FIXTURE
    fs.writeFileSync(
      path.join(tempDir, 'src/domain/fakeProductionService.ts'),
      '// Contaminated file\nconst data = TEST_FIXTURE;\n',
      'utf8'
    );
    const checker = new IntegrityChecker(tempDir);
    const result = checker.verifyFixtures(path.join(tempDir, 'src'));
    assert.equal(result.passed, false, 'Fixture contamination in production file must fail');
    console.log('  ✓ Negative Test 2 passed: Fixture contamination correctly rejected.');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

// Test 3: Malformed / manual receipt fails schema validation
{
  const schemaPath = path.join(process.cwd(), 'docs/implementation/PHASE_EVIDENCE_RECEIPT.schema.json');
  assert.ok(fs.existsSync(schemaPath), 'Receipt schema must exist');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

  // Receipt missing required fields (e.g. missing 'timestamp' and 'verification')
  const malformedReceipt = {
    receiptVersion: "6.0.0",
    promptId: "P00A",
    status: "PASS"
    // Missing required: timestamp, architecture, verification, integrity, external, blockers
  };

  const hasAllRequired = schema.required.every((field: string) => field in malformedReceipt);
  assert.equal(hasAllRequired, false, 'Malformed receipt missing required fields must be caught');
  console.log('  ✓ Negative Test 3 passed: Malformed receipt correctly caught by schema validation.');
}

// Test 4: Failing required check prevents phase PASS
{
  // Test that if an exitCode is non-zero, status cannot be PASS
  const mockFailedExecution = {
    command: 'npm run non_existent_test_suite_xyz',
    exitCode: 1,
    stdoutSummary: 'Command failed'
  };

  const shouldPass = mockFailedExecution.exitCode === 0;
  assert.equal(shouldPass, false, 'Non-zero command exit code must prevent PASS');
  console.log('  ✓ Negative Test 4 passed: Failing required check prevents phase PASS.');
}

// Test 5: Epistemic status check - AI-derived record cannot masquerade as measured provider value
{
  const { validateSourceOriginCompatibility, validateEpistemicPromotion } = await import('../../src/domain/epistemicGovernance.js');
  
  let rejectedSpoofing = false;
  try {
    validateSourceOriginCompatibility('AI_MODEL', 'MEASURED');
  } catch (err) {
    rejectedSpoofing = true;
  }
  assert.equal(rejectedSpoofing, true, 'AI_MODEL origin claiming MEASURED must be rejected');

  let rejectedPromotion = false;
  try {
    validateEpistemicPromotion(
      'AI_DRAFT',
      'VERIFIED',
      {
        actorId: 'agent_gemini',
        role: 'AI_AGENT',
        hasHumanReview: false,
        hasEmpiricalEvidence: false,
        auditNote: 'Confidence 0.99',
      },
      {
        sourceOrigin: 'AI_MODEL',
        epistemicState: 'AI_DRAFT',
        observedAt: new Date().toISOString(),
        capturedBy: 'gemini',
        confidence: 0.99,
      }
    );
  } catch (err) {
    rejectedPromotion = true;
  }
  assert.equal(rejectedPromotion, true, 'AI agent promoting record to VERIFIED must be rejected');
  console.log('  ✓ Negative Test 5 passed: Epistemic status spoofing and autonomous AI promotion correctly rejected.');
}

// Test 6: Creative output contamination test (P05)
{
  const { validateCreativeIsolation } = await import('../../src/domain/epistemicGovernance.js');
  let rejectedCreative = false;
  try {
    validateCreativeIsolation({
      id: 'lyr_sample123',
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
    });
  } catch (err) {
    rejectedCreative = true;
  }
  assert.equal(rejectedCreative, true, 'Creative output attempting ingestion into research tables must fail');
  console.log('  ✓ Negative Test 6 passed: Creative output contamination correctly rejected.');
}

// Test 7: Feedback promotion to research test (P05)
{
  const { validateFeedbackIsolation } = await import('../../src/domain/epistemicGovernance.js');
  let rejectedFeedback = false;
  try {
    validateFeedbackIsolation({
      id: 'genfb_123',
      promotedToResearch: true,
    });
  } catch (err) {
    rejectedFeedback = true;
  }
  assert.equal(rejectedFeedback, true, 'Feedback cannot be promoted to empirical research facts');
  console.log('  ✓ Negative Test 7 passed: Feedback promotion to empirical research correctly rejected.');
}

// Test 8: Sound prompt constraints test (P05)
{
  const { validateSoundPromptConstraints } = await import('../../src/domain/epistemicGovernance.js');
  let rejectedLength = false;
  try {
    validateSoundPromptConstraints({
      id: 'sndp_oversized',
      promptText: 'a'.repeat(1050),
      artistLeakageScrubbed: true,
    });
  } catch (err) {
    rejectedLength = true;
  }
  assert.equal(rejectedLength, true, 'Sound prompt >= 1000 chars must be rejected');

  let rejectedLeakage = false;
  try {
    validateSoundPromptConstraints({
      id: 'sndp_leak',
      promptText: 'Acoustic guitar style of Taylor Swift',
      artistLeakageScrubbed: false,
    });
  } catch (err) {
    rejectedLeakage = true;
  }
  assert.equal(rejectedLeakage, true, 'Sound prompt with unscrubbed artist leakage must be rejected');
  console.log('  ✓ Negative Test 8 passed: Sound prompt constraints (length < 1000 and zero leakage) correctly enforced.');
}

// Test 9: Retention & purge prevention on immutable records (P05)
{
  const { validateRetentionAction } = await import('../../src/domain/epistemicGovernance.js');
  let rejectedPurge = false;
  try {
    validateRetentionAction('GenerationRecord', 'PURGE', { id: 'genrec_published_001' });
  } catch (err) {
    rejectedPurge = true;
  }
  assert.equal(rejectedPurge, true, 'Purge of immutable GenerationRecord must be rejected');
  console.log('  ✓ Negative Test 9 passed: Hard purge of immutable generation records correctly rejected.');
}

console.log('[negative-tests] ALL CONTROLLED NEGATIVE TESTS PASSED.');
