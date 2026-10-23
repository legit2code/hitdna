import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { runDiscoveryJob, NotImplementedError } from '../workers/discovery/index.ts';
import { createTestDb } from '@caim/db/migrator.ts';

describe('Workers: Discovery Worker (runDiscoveryJob)', () => {
  let dbClient: any;
  const tenantId = '22222222-2222-4222-8222-222222222222';

  beforeEach(async () => {
    const memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    dbClient = new pg.Client();
    await dbClient.connect();
  });

  it('acquires authentic files, computes SHA-256 and version records without constants', async () => {
    const file1Content = 'export function calculateTotal(items: number[]): number { return items.reduce((a, b) => a + b, 0); }';
    const file2Content = 'export const APP_CONFIG = { name: "authentic-agent", version: "1.2.0" };';

    const expectedHash1 = `sha256:${crypto.createHash('sha256').update(file1Content).digest('hex')}`;
    const expectedHash2 = `sha256:${crypto.createHash('sha256').update(file2Content).digest('hex')}`;
    const expectedTotalBytes = Buffer.byteLength(file1Content, 'utf8') + Buffer.byteLength(file2Content, 'utf8');

    const result = await runDiscoveryJob({
      sourceType: 'npm',
      targetUrl: 'npm://@caim/sample-agent',
      version: '1.2.0',
      tenantId,
      rawFiles: [
        { path: 'src/calculator.ts', content: file1Content },
        { path: 'src/config.ts', content: file2Content },
      ],
      db: dbClient,
    });

    expect(result.status).toBe('DISCOVERY_COMPLETED');
    expect(result.artifactsCount).toBe(2);
    expect(result.acquiredFilesCount).toBe(2);
    expect(result.totalBytes).toBe(expectedTotalBytes);

    // Assert exact file hashes
    const f1 = result.files.find((f) => f.path === 'src/calculator.ts');
    const f2 = result.files.find((f) => f.path === 'src/config.ts');
    expect(f1?.hash).toBe(expectedHash1);
    expect(f2?.hash).toBe(expectedHash2);

    // Version record
    expect(result.versionRecord).toBeDefined();
    expect(result.versionRecord.versionLabel).toBe('1.2.0');
    expect(result.versionRecord.artifactCount).toBe(2);
    expect(result.versionRecord.totalBytes).toBe(expectedTotalBytes);
    expect(result.versionRecord.contentFingerprint).toBe(result.contentHash);

    // Verify database persistence in source.source_observations, source.artifacts, and intel.evidence
    const obsRows = await dbClient.query(`SELECT * FROM source.source_observations;`);
    expect(obsRows.rows.length).toBeGreaterThanOrEqual(1);
    expect(obsRows.rows[0].source_locator).toBe('npm://@caim/sample-agent');
    expect(obsRows.rows[0].content_hash).toBe(result.contentHash);

    const artRows = await dbClient.query(`SELECT * FROM source.artifacts;`);
    expect(artRows.rows.length).toBeGreaterThanOrEqual(1);
    expect(artRows.rows[0].content_hash).toBe(result.contentHash);

    const evRows = await dbClient.query(`SELECT * FROM intel.evidence WHERE evidence_type = 'METADATA_MANIFEST';`);
    expect(evRows.rows.length).toBeGreaterThanOrEqual(1);
    expect(evRows.rows[0].truth_state).toBe('OBSERVED');
  });

  it('strictly rejects synthetic or mock files with authentic acquisition failure', async () => {
    await expect(
      runDiscoveryJob({
        sourceType: 'github',
        targetUrl: 'https://github.com/example/synthetic-agent',
        rawFiles: [
          {
            path: 'index.ts',
            content: '// Synthetic substitute code placeholder',
            is_synthetic: true,
          },
        ],
      })
    ).rejects.toThrow(/AUTHENTIC_ACQUISITION_FAILED|AUTHENTIC_SOURCE_REQUIRED/);
  });
});
