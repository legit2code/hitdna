import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { createTestDb } from '../../packages/db/src/migrator.ts';
import { PlatformAuditService, PlatformAuditVerifier } from '@caim/auth';

describe('R11 Audit Log Writer Process Restart & Gapless Durability', () => {
  let memDb: any;
  let tcpServer: any;
  let connectionString: string;
  let activeClients: pg.Client[] = [];

  let pgFactory: any;

  beforeAll(async () => {
    if (process.env.DATABASE_URL) {
      connectionString = process.env.DATABASE_URL;
      pgFactory = {
        createClient: () => new pg.Client({ connectionString })
      };
    } else {
      memDb = createTestDb({ applyMigrations: true, applySeed: false });
      const pgAdapter = memDb.adapters.createPg();
      pgFactory = {
        createClient: () => new pgAdapter.Client()
      };
    }

    const initClient = pgFactory.createClient();
    await initClient.connect();
    await initClient.query(
      `INSERT INTO security.tenants (tenant_id, tenant_key, display_name)
       VALUES ('00000000-0000-0000-0000-000000000042', 'restart-test-tenant', 'Restart Test Tenant')
       ON CONFLICT (tenant_id) DO NOTHING;`
    );
    await initClient.end().catch(() => {});
  });

  afterAll(async () => {
    for (const c of activeClients) {
      try {
        if ((c as any).connection?.stream) {
          (c as any).connection.stream.destroy();
        } else {
          await c.end().catch(() => {});
        }
      } catch {}
    }
    if (tcpServer) {
      await tcpServer.close?.();
    }
  });

  it('kill and restart the writer; chain continues without gap', async () => {
    const tenantId = '00000000-0000-0000-0000-000000000042';
    const streamId = `tenant:${tenantId}`;

    // --- PHASE 1: First writer instance (simulating worker process 1) ---
    const client1 = pgFactory.createClient();
    await client1.connect();
    activeClients.push(client1);

    const writer1 = new PlatformAuditService(client1);
    const phase1Records = [];
    for (let i = 1; i <= 10; i++) {
      const rec = await writer1.recordAuditEntry({
        principal_id: `user-pre-restart-${i}`,
        tenant_id: tenantId,
        action: 'KEY_ROTATION',
        target_entity_type: 'KMS_KEY',
        target_entity_id: `key-${i}`,
        outcome: 'SUCCESS',
        criticality: 'SECURITY_CRITICAL',
        details: { phase: 1, iteration: i },
      });
      phase1Records.push(rec);
    }

    expect(phase1Records).toHaveLength(10);
    expect(phase1Records[phase1Records.length - 1].sequence_number).toBe(10);

    // --- PHASE 2: Abruptly terminate writer 1 (simulating process crash / SIGKILL) ---
    if ((client1 as any).connection?.stream) {
      (client1 as any).connection.stream.destroy();
    } else {
      await client1.end().catch(() => {});
    }
    const idx = activeClients.indexOf(client1);
    if (idx !== -1) activeClients.splice(idx, 1);

    // --- PHASE 3: New writer instance boots up (simulating fresh restart / new container) ---
    const client2 = pgFactory.createClient();
    await client2.connect();
    activeClients.push(client2);

    // Writer 2 has no shared in-memory state with writer 1
    const writer2 = new PlatformAuditService(client2);
    const phase2Records = [];
    for (let i = 11; i <= 25; i++) {
      const rec = await writer2.recordAuditEntry({
        principal_id: `user-post-restart-${i}`,
        tenant_id: tenantId,
        action: 'KEY_ROTATION',
        target_entity_type: 'KMS_KEY',
        target_entity_id: `key-${i}`,
        outcome: 'SUCCESS',
        criticality: 'SECURITY_CRITICAL',
        details: { phase: 2, iteration: i },
      });
      phase2Records.push(rec);
    }

    expect(phase2Records).toHaveLength(15);
    expect(phase2Records[0].sequence_number).toBe(11);
    // Cryptographic continuity across restart:
    expect(phase2Records[0].previous_hash).toBe(phase1Records[9].hash);

    // --- PHASE 4: Query full audit trail from database and verify ---
    const dbRes = await client2.query(
      `SELECT * FROM security.platform_audit_log
       WHERE stream_id = $1
       ORDER BY sequence_number ASC;`,
      [streamId]
    );

    const allRows = dbRes.rows.map((row: any) => ({
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

    expect(allRows).toHaveLength(25);

    // Verify sequences are strictly 1..25 without gap
    const sequences = allRows.map(r => r.sequence_number);
    expect(sequences).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));

    // Verify hash chaining is completely unbroken
    for (let i = 1; i < allRows.length; i++) {
      expect(allRows[i].previous_hash).toBe(allRows[i - 1].hash);
    }

    // Verify cryptographic verifier verifies entire chain across the restart boundary
    const report = PlatformAuditVerifier.verifyChain(allRows);
    expect(report.valid).toBe(true);
    expect(report.violations).toHaveLength(0);
    expect(report.totalVerified).toBe(25);
    expect(report.chainHeadHash).toBe(allRows[24].hash);

    // Verify database head
    const headRes = await client2.query(
      `SELECT seq, hash FROM security.audit_chain_head WHERE stream_id = $1;`,
      [streamId]
    );
    expect(headRes.rows).toHaveLength(1);
    expect(Number(headRes.rows[0].seq)).toBe(25);
    expect(headRes.rows[0].hash).toBe(allRows[24].hash);
  });
});
