import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { createTestDb } from '../../packages/db/src/migrator.ts';
import { PlatformAuditService, PlatformAuditVerifier, GENESIS_AUDIT_HASH } from '@caim/auth';

describe('R11 Audit Log Concurrency & Tamper-Evident Durability', () => {
  let memDb: any;
  let tcpServer: any;
  let connectionString: string;
  let clients: pg.Client[] = [];

  beforeAll(async () => {
    if (process.env.DATABASE_URL) {
      connectionString = process.env.DATABASE_URL;
      clients = [
        new pg.Client({ connectionString }),
        new pg.Client({ connectionString }),
        new pg.Client({ connectionString }),
      ];
      await Promise.all(clients.map(c => c.connect()));
    } else {
      memDb = createTestDb({ applyMigrations: true, applySeed: false });
      const pgAdapter = memDb.adapters.createPg();
      clients = [
        new pgAdapter.Client(),
        new pgAdapter.Client(),
        new pgAdapter.Client(),
      ];
      await Promise.all(clients.map(c => c.connect()));
    }

    // Seed test tenant to satisfy foreign key constraint
    await clients[0].query(
      `INSERT INTO security.tenants (tenant_id, tenant_key, display_name)
       VALUES ('00000000-0000-0000-0000-000000000001', 'concurrency-test-tenant', 'Concurrency Test Tenant')
       ON CONFLICT (tenant_id) DO NOTHING;`
    );
  });

  afterAll(async () => {
    for (const c of clients) {
      if ((c as any).connection?.stream) {
        (c as any).connection.stream.destroy();
      } else {
        await c.end().catch(() => {});
      }
    }
    if (tcpServer) {
      await tcpServer.close?.();
    }
  });

  it('50 parallel writers across 3 connections → strictly increasing seq, no forks, verifier passes', async () => {
    const tenantId = '00000000-0000-0000-0000-000000000001';
    const totalWriters = 50;

    // Dispatch 50 concurrent writers across the 3 connection clients
    const writePromises = Array.from({ length: totalWriters }, (_, i) => {
      const client = clients[i % clients.length];
      const auditService = new PlatformAuditService(client);

      return auditService.recordAuditEntry({
        principal_id: `writer-user-${i}`,
        tenant_id: tenantId,
        action: 'ROLE_ASSIGNED',
        target_entity_type: 'ROLE',
        target_entity_id: `role-grant-${i}`,
        outcome: 'SUCCESS',
        criticality: 'SECURITY_CRITICAL',
        details: { writerIndex: i, workerPid: 1000 + (i % 3) },
      });
    });

    const writtenRecords = await Promise.all(writePromises);
    expect(writtenRecords).toHaveLength(totalWriters);

    // Query authoritative records from the database directly, sorted by sequence_number
    const queryClient = clients[0];
    const streamId = `tenant:${tenantId}`;
    const dbRes = await queryClient.query(
      `SELECT * FROM security.platform_audit_log
       WHERE stream_id = $1
       ORDER BY sequence_number ASC;`,
      [streamId]
    );

    const records = dbRes.rows.map((row: any) => ({
      audit_id: String(row.audit_id),
      sequence_number: Number(row.sequence_number),
      principal_id: String(row.principal_id),
      tenant_id: row.tenant_id ? String(row.tenant_id) : null,
      action: String(row.action),
      target_entity_type: String(row.target_entity_type),
      target_entity_id: String(row.target_entity_id),
      timestamp: typeof row.timestamp === 'string' ? row.timestamp : new Date(row.timestamp).toISOString(),
      outcome: row.outcome,
      criticality: row.criticality,
      classification: row.classification,
      client_ip: row.client_ip || null,
      user_agent: row.user_agent || null,
      correlation_id: row.correlation_id || null,
      details: typeof row.details === 'string' ? JSON.parse(row.details) : (row.details || {}),
      previous_hash: String(row.previous_hash),
      hash: String(row.hash),
      signature_sha256: String(row.hash),
      persisted_to_db: true,
      authoritative: true,
      stream_id: String(row.stream_id),
      hash_algorithm: String(row.hash_algorithm),
    }));

    expect(records).toHaveLength(totalWriters);

    // 1. Verify strictly monotonic sequence numbers: 1..50 with NO gaps and NO duplicates
    const sequenceNumbers = records.map(r => r.sequence_number);
    const expectedSequences = Array.from({ length: totalWriters }, (_, i) => i + 1);
    expect(sequenceNumbers).toEqual(expectedSequences);

    // 2. Verify NO forks: each record's previous_hash equals preceding record's digest
    expect(records[0].previous_hash).toBe(GENESIS_AUDIT_HASH);
    for (let i = 1; i < records.length; i++) {
      expect(records[i].previous_hash).toBe(records[i - 1].hash);
      expect(records[i].hash).not.toBe(records[i - 1].hash);
    }

    // 3. Verify cryptographic verifier verifies all 50 records with zero violations
    const report = PlatformAuditVerifier.verifyChain(records);
    expect(report.valid).toBe(true);
    expect(report.totalVerified).toBe(totalWriters);
    expect(report.violations).toHaveLength(0);
    expect(report.chainHeadHash).toBe(records[totalWriters - 1].hash);

    // 4. Verify chain head record in security.audit_chain_head matches the head of the chain
    const headRes = await queryClient.query(
      `SELECT seq, hash FROM security.audit_chain_head WHERE stream_id = $1;`,
      [streamId]
    );
    expect(headRes.rows).toHaveLength(1);
    expect(Number(headRes.rows[0].seq)).toBe(totalWriters);
    expect(headRes.rows[0].hash).toBe(records[totalWriters - 1].hash);
  });
});
