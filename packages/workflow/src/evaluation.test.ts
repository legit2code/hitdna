/**
 * Golden Corpus, Evaluation & CI Regression Gate Test Suite
 * Conforming to P31 specification
 */

import { describe, it, expect } from 'vitest';
import { runEvaluationVerificationTests, globalEvaluationEngine } from './evaluation.ts';

export { runEvaluationVerificationTests };

describe('Golden Corpus & Regression Evaluation Verification', () => {
  const res = runEvaluationVerificationTests();

  it.each(res.testResults)('$name', (check) => {
    expect(
      check.status,
      `Verification check "${check.name}" failed: ${check.details}`
    ).toBe('PASS');
  });

  it('runs live pipeline over golden corpus samples and verifies precision/recall thresholds', async () => {
    const { report, evaluationRun } = await globalEvaluationEngine.evaluateEngineVersionAsync();
    expect(report.totalSamples).toBeGreaterThanOrEqual(100);
    expect(report.aggregate.f1Score).toBeGreaterThanOrEqual(0.95);
    expect(report.aggregate.precision).toBeGreaterThanOrEqual(0.95);
    expect(report.aggregate.recall).toBeGreaterThanOrEqual(0.95);
    expect(report.tolerancePassed).toBe(true);
    expect(evaluationRun.gateStatus).toBe('PASSED');
  }, 60000);
});
