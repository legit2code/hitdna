import { describe, it, expect, beforeEach } from 'vitest';
import path from 'node:path';
import { runEvaluationJob, NotImplementedError } from '../workers/evaluation/index.ts';
import { createTestDb } from '@caim/db/migrator.ts';

describe('Workers: Evaluation Worker (runEvaluationJob)', () => {
  let dbClient: any;

  beforeEach(async () => {
    const memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    dbClient = new pg.Client();
    await dbClient.connect();
  });

  it('executes real golden-corpus evaluation with corpus/ fixtures and returns computed metrics without constants', async () => {
    const result = await runEvaluationJob({
      suiteId: 'ci-golden-corpus',
      goldenCorpusVersion: '2.0.1',
      engineVersion: '2.0.1-v2',
      tenantId: '11111111-1111-4111-8111-111111111111',
      db: dbClient,
    });

    expect(result.status).toBeDefined();
    expect(result.runId).toBeDefined();
    expect(result.signatureSha256).toHaveLength(64);

    // Assert counts and metrics are real numbers derived dynamically
    expect(result.metrics.totalFixturesEvaluated).toBeGreaterThan(0);
    expect(typeof result.metrics.f1Score).toBe('number');
    expect(typeof result.metrics.precision).toBe('number');
    expect(typeof result.metrics.recall).toBe('number');
    expect(result.metrics.f1Score).toBeGreaterThan(0);
    expect(result.metrics.precision).toBeGreaterThan(0);
    expect(result.metrics.recall).toBeGreaterThan(0);

    // Confusion matrix totals should match evaluated fixtures count
    const cm = result.metrics;
    expect(cm.truePositives + cm.falsePositives + cm.trueNegatives + cm.falseNegatives).toBe(
      cm.totalFixturesEvaluated
    );

    // Gate decision
    expect(result.decision).toBeDefined();
    expect(result.decision.engineVersion).toBe('2.0.1-v2');
    expect(typeof result.decision.canDeployToProduction).toBe('boolean');

    // Verify persistence in ops.evaluation_runs
    const runRows = await dbClient.query(`SELECT * FROM ops.evaluation_runs;`);
    expect(runRows.rows.length).toBeGreaterThanOrEqual(1);
    expect(runRows.rows[0].engine_key).toBe('caim-evaluator');
  });

  it('strictly throws CORPUS_NOT_FOUND when corpus directory does not exist', async () => {
    const missingCorpusPath = path.resolve(process.cwd(), 'does-not-exist-corpus-xyz');

    await expect(
      runEvaluationJob({
        corpusDir: missingCorpusPath,
      })
    ).rejects.toThrow(/CORPUS_NOT_FOUND/);
  });

  it('exports typed NotImplementedError for unimplemented entrypoints', () => {
    const err = new NotImplementedError('FutureWorker');
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe('ERR_NOT_IMPLEMENTED');
    expect(err.retryable).toBe(false);
  });
});
