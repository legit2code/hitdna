/**
 * Collapse Test: Inverted / Deliberately Wrong Labels (R10 Task 1)
 *
 * Runs the evaluator on the golden corpus, but compares the actual engine outputs
 * against deliberately wrong / inverted ground truth labels.
 * Asserts that the metrics collapse, proving there is no self-fulfilling label leakage.
 */

import { describe, it, expect } from 'vitest';
import {
  CorpusLoader,
  CorpusPipelineRunner,
  CorpusScorer,
  CorpusSampleLabel,
} from '../../packages/workflow/src/evaluation.ts';

describe('Golden Evaluator Collapse Test (R10 Task 1)', () => {
  it('metrics collapse when evaluated against deliberately inverted labels', async () => {
    const { samples, labels } = CorpusLoader.loadCorpus();
    expect(samples.length).toBeGreaterThanOrEqual(80);

    // Run real pipeline over authentic samples
    const sampleOutputs = await CorpusPipelineRunner.runAll(samples);

    // 1. Normal evaluation should succeed with high metrics
    const genuineReport = CorpusScorer.score(sampleOutputs, labels);
    expect(genuineReport.aggregate.precision).toBeGreaterThanOrEqual(0.95);
    expect(genuineReport.aggregate.recall).toBeGreaterThanOrEqual(0.95);
    expect(genuineReport.aggregate.f1Score).toBeGreaterThanOrEqual(0.95);

    // 2. Deliberately inverted labels (Malicious -> Benign, Benign -> Malicious)
    const invertedLabels = new Map<string, CorpusSampleLabel>();
    for (const [id, label] of labels.entries()) {
      invertedLabels.set(id, {
        ...label,
        isMalicious: !label.isMalicious,
        expectedVerdict: label.expectedVerdict === 'BLOCKED' ? 'CLEARED' : 'BLOCKED',
      });
    }

    // Score actual outputs against inverted labels
    const collapsedReport = CorpusScorer.score(sampleOutputs, invertedLabels);

    // Inverted ground-truth must cause metrics to collapse
    console.log('Genuine F1:', genuineReport.aggregate.f1Score, 'Collapsed F1:', collapsedReport.aggregate.f1Score);
    expect(collapsedReport.aggregate.f1Score).toBeLessThanOrEqual(0.10);
    expect(collapsedReport.aggregate.precision).toBeLessThanOrEqual(0.10);
    expect(collapsedReport.aggregate.recall).toBeLessThanOrEqual(0.10);
  }, 60000);
});
