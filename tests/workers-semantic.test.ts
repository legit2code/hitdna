import { describe, it, expect, beforeEach } from 'vitest';
import { runSemanticJob, NotImplementedError } from '../workers/semantic/index.ts';
import { createTestDb } from '@caim/db/migrator.ts';

describe('Workers: Semantic Worker (runSemanticJob)', () => {
  let dbClient: any;
  const tenantId = '33333333-3333-4333-8333-333333333333';

  beforeEach(async () => {
    const memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    dbClient = new pg.Client();
    await dbClient.connect();
  });

  it('parses authentic TypeScript sources and extracts real AST node and symbol counts', async () => {
    const source1 = `
      export class OrchestratorService {
        private activeCount: number = 0;
        public startTask(taskId: string): boolean {
          this.activeCount++;
          return true;
        }
        public stopTask(): void {
          this.activeCount--;
        }
      }
      export function helperUtility(val: string): string {
        return val.trim().toLowerCase();
      }
    `;

    const result = await runSemanticJob({
      artifactId: 'art-semantic-test-1',
      sourceFiles: [
        { path: 'src/orchestrator.ts', content: source1 },
      ],
      tenantId,
      db: dbClient,
    });

    expect(result.status).toBe('SEMANTIC_ANALYSIS_COMPLETED');
    expect(result.artifactId).toBe('art-semantic-test-1');
    expect(result.parsedFilesCount).toBe(1);
    expect(result.totalFilesCount).toBe(1);

    // Symbols extracted: OrchestratorService (class), activeCount (prop), startTask (method), stopTask (method), helperUtility (func)
    expect(result.symbolsCount).toBeGreaterThanOrEqual(4);
    expect(result.astNodesCount).toBeGreaterThanOrEqual(result.symbolsCount);

    // Symbol graph
    expect(result.symbolGraph).toBeDefined();

    // Database evidence row
    const evRows = await dbClient.query(`SELECT * FROM intel.evidence WHERE evidence_type = 'AST_MATCH';`);
    expect(evRows.rows.length).toBeGreaterThanOrEqual(1);
    expect(evRows.rows[0].truth_state).toBe('STATICALLY_DERIVED');
  });

  it('dynamically increases AST and symbol counts when code complexity increases', async () => {
    const simpleCode = 'export const a = 1;';
    const complexCode = `
      export const a = 1;
      export function foo() { return 42; }
      export function bar() { return foo(); }
      export class Baz { run() {} }
    `;

    const resSimple = await runSemanticJob({
      artifactId: 'art-simple',
      sourceFiles: [{ path: 'simple.ts', content: simpleCode }],
    });

    const resComplex = await runSemanticJob({
      artifactId: 'art-complex',
      sourceFiles: [{ path: 'complex.ts', content: complexCode }],
    });

    expect(resComplex.symbolsCount).toBeGreaterThan(resSimple.symbolsCount);
    expect(resComplex.astNodesCount).toBeGreaterThan(resSimple.astNodesCount);
  });

  it('strictly throws when authentic source files are empty or missing', async () => {
    await expect(
      runSemanticJob({
        artifactId: 'art-empty',
        sourceFiles: [],
      })
    ).rejects.toThrow(/AUTHENTIC_SOURCE_REQUIRED/);
  });
});
