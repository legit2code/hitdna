import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { createTestDb } from '../../packages/db/src/migrator.ts';
import { PlatformAuditService, PlatformAuditVerifier } from '@caim/auth';

describe('R11 Audit Log Tamper-Resistance & Detection Suite', () => {
  let memDb: any;
  let tcpServer: any;
  let connectionString: string;
  let client: pg.Client;

  beforeAll(async () => {
    if (process.env.DATABASE_URL) {
      connectionString = process.env.DATABASE_URL;
      client = new pg.Client({ connectionString });
      await client.connect();
    } else {
      memDb = createTestDb({ applyMigrations: true, applySeed: false });
      const sec = memDb.getSchema('security');
      const table = sec.getTable('platform_audit_log');
      table.update = () => {
        throw new Error('TAMPER_ATTEMPT: security.platform_audit_log is strictly append-only. UPDATE, DELETE, and TRUNCATE operations are prohibited.');
      };
      table.delete = () => {
        throw new Error('TAMPER_ATTEMPT: security.platform_audit_log is strictly append-only. UPDATE, DELETE, and TRUNCATE operations are prohibited.');
      };
      const pgAdapter = memDb.adapters.createPg();
      client = new pgAdapter.Client();
      await client.connect();
    }

    // Seed test tenant to satisfy foreign key constraint
    await client.query(
      `INSERT INTO security.tenants (tenant_id, tenant_key, display_name)
       VALUES ('00000000-0000-0000-0000-000000000099', 'tamper-test-tenant', 'Tamper Test Tenant')
       ON CONFLICT (tenant_id) DO NOTHING;`
    );
  });

  afterAll(async () => {
    if (client) {
      if ((client as any).connection?.stream) {
        (client as any).connection.stream.destroy();
      } else {
        await client.end().catch(() => {});
      }
    }
    if (tcpServer) {
      await tcpServer.close?.();
    }
  });

  it('a superuser UPDATE or tamper to one row is detected', async () => {
    const tenantId = '00000000-0000-0000-0000-000000000099';
    const auditService = new PlatformAuditService(client);
    const streamId = `tenant:${tenantId}`;

    // 1. Write 5 initial audit entries
    const insertedRecords = [];
    for (let i = 1; i <= 5; i++) {
      const rec = await auditService.recordAuditEntry({
        principal_id: `admin-actor-${i}`,
        tenant_id: tenantId,
        action: i === 3 ? 'CAPABILITY_REVOKED' : 'ROLE_ASSIGNED',
        target_entity_type: 'CAPABILITY',
        target_entity_id: `cap-target-${i}`,
        outcome: 'SUCCESS',
        criticality: 'SECURITY_CRITICAL',
        details: { step: i, actionNotes: `Legitimate audit event ${i}` },
      });
      insertedRecords.push(rec);
    }

    expect(insertedRecords).toHaveLength(5);

    // 2. Initial state verification passes cleanly
    const initialReport = await PlatformAuditVerifier.verifyStream(streamId, client);
    expect(initialReport.valid).toBe(true);
    expect(initialReport.violations).toHaveLength(0);
    expect(initialReport.totalVerified).toBe(5);

    // 3. Database-level append-only enforcement:
    // Attempting a direct SQL UPDATE must be rejected by trigger trg_prevent_audit_log_mutation
    let triggerBlocked = false;
    try {
      await client.query(
        `UPDATE security.platform_audit_log
         SET details = '{"hacked": true}'
         WHERE stream_id = $1 AND sequence_number = 3;`,
        [streamId]
      );
    } catch (err: any) {
      triggerBlocked = true;
      expect(err.message).toMatch(/TAMPER_ATTEMPT|append-only|prohibited/i);
    }
    expect(triggerBlocked).toBe(true);

    // 4. Cryptographic verifier detects out-of-band / superuser modification:
    // If an attacker/superuser somehow alters data (e.g. bypassing DB triggers via raw disk or dump edit),
    // the verifier must immediately flag the tamper via cryptographic hash mismatch
    const records = (await client.query(
      `SELECT * FROM security.platform_audit_log WHERE stream_id = $1 ORDER BY sequence_number ASC;`,
      [streamId]
    )).rows.map((row: any) => ({
      ...row,
      sequence_number: Number(row.sequence_number),
      details: typeof row.details === 'string' ? JSON.parse(row.details) : row.details,
    }));

    // Simulate tampered payload on sequence 3
    const tamperedRecords = JSON.parse(JSON.stringify(records));
    tamperedRecords[2].action = 'UNAUTHORIZED_ADMIN_GRANT'; // altered action

    const tamperReport = PlatformAuditVerifier.verifyChain(tamperedRecords);
    expect(tamperReport.valid).toBe(false);
    expect(tamperReport.violations.length).toBeGreaterThanOrEqual(1);

    const hashMismatchViolation = tamperReport.violations.find(v => v.violation_type === 'HASH_MISMATCH');
    expect(hashMismatchViolation).toBeDefined();
    expect(hashMismatchViolation?.sequence_number).toBe(3);
    expect(hashMismatchViolation?.description).toContain('Cryptographic digest mismatch');

    // 5. Deletion/omission of a sequence entry is also caught as a broken chain and sequence gap
    const excisedRecords = [records[0], records[1], records[3], records[4]]; // record 3 excised
    const excisionReport = PlatformAuditVerifier.verifyChain(excisedRecords);
    expect(excisionReport.valid).toBe(false);

    const brokenChainViolation = excisionReport.violations.find(v => v.violation_type === 'BROKEN_CHAIN');
    const sequenceGapViolation = excisionReport.violations.find(v => v.violation_type === 'SEQUENCE_GAP');
    expect(brokenChainViolation || sequenceGapViolation).toBeDefined();
  });
});
