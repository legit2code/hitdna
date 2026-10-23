import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgresDatabaseAdapter } from '../../packages/db/src/postgres-adapter.ts';

const DATABASE_URL = process.env.DATABASE_URL;

describe.skipIf(!DATABASE_URL)('System-Scoped Transaction & Audit Enforcement (R05)', () => {
  let adapter: PostgresDatabaseAdapter;

  beforeAll(async () => {
    adapter = new PostgresDatabaseAdapter({
      connectionString: DATABASE_URL,
      applicationName: 'test-system-tx',
    });
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('withSystemTx without a principal throws security boundary error', async () => {
    await expect(
      adapter.withSystemTx(
        { actor: 'unknown-actor', reason: 'Attempting without principal' } as any,
        async (tx) => tx.query('SELECT 1;')
      )
    ).rejects.toThrow(/Denied: withSystemTx requires an authenticated service-account principal with the "system.db" capability/);
  });

  it('withSystemTx with a normal human user principal throws security boundary error', async () => {
    const humanPrincipal = {
      principal_id: 'usr-human-analyst',
      is_authenticated: true,
      roles: ['analyst'],
      tenant_id: '00000000-0000-0000-0000-000000000001',
      is_service: false,
      capabilities: ['report:generate'],
    };

    await expect(
      adapter.withSystemTx(
        { actor: 'usr-human-analyst', reason: 'Ad-hoc query', principal: humanPrincipal },
        async (tx) => tx.query('SELECT 1;')
      )
    ).rejects.toThrow(/Denied: withSystemTx requires an authenticated service-account principal with the "system.db" capability/);
  });

  it('withSystemTx with service principal lacking system.db capability throws', async () => {
    const unprivilegedService = {
      principal_id: 'service-mailer',
      is_authenticated: true,
      roles: ['service'],
      is_service: true,
      capabilities: ['email:send'],
    };

    await expect(
      adapter.withSystemTx(
        { actor: 'service-mailer', reason: 'Worker processing', principal: unprivilegedService },
        async (tx) => tx.query('SELECT 1;')
      )
    ).rejects.toThrow(/Denied: withSystemTx requires an authenticated service-account principal with the "system.db" capability/);
  });

  it('withSystemTx with valid service principal holding system.db capability succeeds and writes audit row with reason', async () => {
    const validServicePrincipal = {
      principal_id: 'service-discovery-engine',
      is_authenticated: true,
      roles: ['service'],
      is_service: true,
      capabilities: ['system.db'],
    };

    const auditActor = 'service-discovery-engine';
    const auditReason = 'Scheduled background discovery run - cycle #4028';

    const result = await adapter.withSystemTx(
      { actor: auditActor, reason: auditReason, principal: validServicePrincipal },
      async (tx) => {
        expect(tx.isSystem).toBe(true);
        expect(tx.actor).toBe(auditActor);
        expect(tx.reason).toBe(auditReason);
        const queryRes = await tx.query('SELECT 100 AS num;');
        return queryRes.rows[0].num;
      }
    );

    expect(result).toBe(100);

    // Verify audit row was persisted in security.system_tx_audit
    const auditRes = await adapter.query(
      `SELECT * FROM security.system_tx_audit WHERE actor = $1 AND reason = $2 ORDER BY created_at DESC LIMIT 1;`,
      [auditActor, auditReason]
    );

    expect(auditRes.rows.length).toBe(1);
    expect(auditRes.rows[0].actor).toBe(auditActor);
    expect(auditRes.rows[0].reason).toBe(auditReason);

    // Verify platform audit log also recorded the transaction
    const platformAudit = await adapter.query(
      `SELECT * FROM security.platform_audit_log WHERE principal_id = $1 AND action = 'SYSTEM_TX' ORDER BY timestamp DESC LIMIT 1;`,
      [auditActor]
    );
    expect(platformAudit.rows.length).toBe(1);
    expect(platformAudit.rows[0].outcome).toBe('SUCCESS');
  });
});
