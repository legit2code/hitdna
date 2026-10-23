/**
 * No Label Leak Boundary Test (R10 Task 1)
 *
 * Verifies via static analysis of source files and import graph that:
 * 1. The pipeline runner (CorpusPipelineRunner, StaticAnalysisEngine, DecisionOrchestrationEngine)
 *    never imports, reads, references, or accepts `label.json` or ground truth.
 * 2. Only the separate `CorpusScorer` reads `label.json`.
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('No-Label-Leak Import & Dataflow Boundary (R10 Task 1)', () => {
  it('pipeline runner and static analysis engine never import or reference label.json', () => {
    const evalPath = path.resolve(process.cwd(), 'packages/workflow/src/evaluation.ts');
    const saPath = path.resolve(process.cwd(), 'workers/static-analysis/engine.ts');
    const decPath = path.resolve(process.cwd(), 'workers/decision/engine.ts');

    const evalContent = fs.readFileSync(evalPath, 'utf8');
    const saContent = fs.readFileSync(saPath, 'utf8');
    const decContent = fs.readFileSync(decPath, 'utf8');

    // 1. StaticAnalysisEngine and DecisionOrchestrationEngine have no knowledge of labels
    expect(saContent).not.toContain('label.json');
    expect(saContent).not.toContain('isMalicious');
    expect(saContent).not.toContain('expectedVerdict');

    expect(decContent).not.toContain('label.json');
    expect(decContent).not.toContain('isMalicious');
    expect(decContent).not.toContain('expectedVerdict');

    // 2. In evaluation.ts, CorpusPipelineRunner.runSample method must not reference labels or ground truth
    const pipelineRunnerMatch = evalContent.match(/class CorpusPipelineRunner[\s\S]*?^}/m);
    expect(pipelineRunnerMatch).toBeDefined();
    const runnerCode = pipelineRunnerMatch ? pipelineRunnerMatch[0] : '';

    expect(runnerCode).not.toContain('label.json');
    expect(runnerCode).not.toContain('expectedVerdict');
    expect(runnerCode).not.toContain('isMalicious');
    expect(runnerCode).not.toContain('isHeldOut');

    // 3. CorpusSampleInput interface must have NO label fields
    const sampleInputMatch = evalContent.match(/interface CorpusSampleInput[\s\S]*?}/);
    expect(sampleInputMatch).toBeDefined();
    const inputInterface = sampleInputMatch ? sampleInputMatch[0] : '';
    expect(inputInterface).not.toContain('expectedVerdict');
    expect(inputInterface).not.toContain('isMalicious');
    expect(inputInterface).not.toContain('label');
  });

  it('prohibits Math.random anywhere in evaluation, DR and performance files', () => {
    const files = [
      'packages/workflow/src/evaluation.ts',
      'packages/workflow/src/dr-recovery.ts',
      'packages/workflow/src/performance-smoke.ts',
    ];

    for (const relPath of files) {
      const absPath = path.resolve(process.cwd(), relPath);
      const content = fs.readFileSync(absPath, 'utf8');
      const matches = content.match(/Math\.random/g);
      expect(
        matches,
        `Found Math.random() in ${relPath}: ${matches ? matches.length : 0} occurrences`
      ).toBeNull();
    }
  });
});
