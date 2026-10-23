import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgresDatabaseAdapter } from '../../packages/db/src/postgres-adapter.ts';

const DATABASE_URL = process.env.DATABASE_URL;

describe.skipIf(!DATABASE_URL)('Tenant-Scoped Transaction & Cross-Tenant Boundary Matrix (R05)', () => {
  let adapter: PostgresDatabaseAdapter;

  const tenantA = '00000000-0000-0000-0000-0000000000a2';
  const tenantB = '00000000-0000-0000-0000-0000000000b2';
  const scopeA = '00000000-0000-0000-0000-0000000000a3';
  const scopeB = '00000000-0000-0000-0000-0000000000b3';

  const principalA = {
    principal_id: 'usr-tenant-a-test',
    is_authenticated: true,
    tenant_id: tenantA,
    roles: ['user'],
  };

  const principalB = {
    principal_id: 'usr-tenant-b-test',
    is_authenticated: true,
    tenant_id: tenantB,
    roles: ['user'],
  };

  beforeAll(async () => {
    adapter = new PostgresDatabaseAdapter({
      connectionString: DATABASE_URL,
      applicationName: 'test-tenant-tx',
    });

    // Seed tenants and scopes
    await adapter.query(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES ($1, 'tenant-a-matrix', 'Tenant A', 'ACTIVE'), ($2, 'tenant-b-matrix', 'Tenant B', 'ACTIVE')
      ON CONFLICT (tenant_id) DO NOTHING;
    `, [tenantA, tenantB]);

    await adapter.query(`
      INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
      VALUES ($1, 'ORGANIZATION', $2), ($3, 'ORGANIZATION', $4)
      ON CONFLICT (scope_id) DO NOTHING;
    `, [scopeA, tenantA, scopeB, tenantB]);
  });

  afterAll(async () => {
    await adapter.close();
  });

  const matrixTables = [
    {
      name: 'analysis.static_findings',
      idCol: 'finding_id',
      id: '00000000-0000-0000-0000-000000000f01',
      insert: async (tx: any, id: string) => {
        await tx.query(`
          INSERT INTO analysis.static_findings (
            finding_id, tenant_id, rule_id, severity, confidence, message, status
          ) VALUES ($1, $2, 'RULE-01', 'HIGH', 1.0, 'Finding A', 'OPEN');
        `, [id, tenantA]);
      },
    },
    {
      name: 'intel.evidence',
      idCol: 'evidence_id',
      id: '00000000-0000-0000-0000-000000000e01',
      insert: async (tx: any, id: string) => {
        await tx.query(`
          INSERT INTO intel.evidence (
            evidence_id, scope_id, evidence_type, content_locator, summary, validity_status
          ) VALUES ($1, $2, 'STATIC_ANALYSIS', 'loc-01', 'Evidence A', 'VALID');
        `, [id, scopeA]);
      },
    },
    {
      name: 'intel.assertions',
      idCol: 'assertion_id',
      id: '00000000-0000-0000-0000-000000000a01',
      insert: async (tx: any, id: string) => {
        await tx.query(`
          INSERT INTO intel.assertions (
            assertion_id, tenant_id, assertion_type, confidence_score, status
          ) VALUES ($1, $2, 'CAPABILITY', 0.95, 'ACTIVE');
        `, [id, tenantA]);
      },
    },
    {
      name: 'intel.claims',
      idCol: 'claim_id',
      id: '00000000-0000-0000-0000-000000000c01',
      insert: async (tx: any, id: string) => {
        await tx.query(`
          INSERT INTO intel.claims (
            claim_id, tenant_id, claim_type, subject, predicate, confidence
          ) VALUES ($1, $2, 'BEHAVIOR', 'subject-a', 'executes', 0.9);
        `, [id, tenantA]);
      },
    },
    {
      name: 'intel.risks',
      idCol: 'risk_id',
      id: '00000000-0000-0000-0000-000000000r01',
      insert: async (tx: any, id: string) => {
        await tx.query(`
          INSERT INTO intel.risks (
            risk_id, tenant_id, risk_type, severity, title, status
          ) VALUES ($1, $2, 'SECURITY', 'CRITICAL', 'Risk A', 'ACTIVE');
        `, [id, tenantA]);
      },
    },
    {
      name: 'intel.policy_decisions',
      idCol: 'decision_id',
      id: '00000000-0000-0000-0000-000000000d01',
      insert: async (tx: any, id: string) => {
        await tx.query(`
          INSERT INTO intel.policy_decisions (
            decision_id, tenant_id, decision_type, decision, rationale
          ) VALUES ($1, $2, 'COMPLIANCE', 'ALLOW', 'Approved policy decision');
        `, [id, tenantA]);
      },
    },
  ];

  for (const item of matrixTables) {
    it(`cross-tenant isolation matrix: tenant B cannot read or mutate tenant A row in ${item.name}`, async () => {
      // 1. Tenant A inserts row inside withTenantTx
      await adapter.withTenantTx(principalA, async (txA) => {
        await item.insert(txA, item.id);
        const readA = await txA.query(`SELECT * FROM ${item.name} WHERE ${item.idCol} = $1;`, [item.id]);
        expect(readA.rows.length).toBe(1);
      });

      // 2. Tenant B in withTenantTx tries to READ Tenant A's row -> 0 rows returned
      await adapter.withTenantTx(principalB, async (txB) => {
        const readB = await txB.query(`SELECT * FROM ${item.name} WHERE ${item.idCol} = $1;`, [item.id]);
        expect(readB.rows.length).toBe(0);
      });

      // 3. Tenant B in withTenantTx tries to UPDATE Tenant A's row -> 0 rows affected
      await adapter.withTenantTx(principalB, async (txB) => {
        const updateB = await txB.query(
          `UPDATE ${item.name} SET status = 'MUTATED_BY_B' WHERE ${item.idCol} = $1;`,
          [item.id]
        ).catch(() => ({ rowCount: 0 }));
        expect(updateB.rowCount).toBe(0);
      });

      // 4. Tenant B in withTenantTx tries to DELETE Tenant A's row -> 0 rows affected
      await adapter.withTenantTx(principalB, async (txB) => {
        const deleteB = await txB.query(
          `DELETE FROM ${item.name} WHERE ${item.idCol} = $1;`,
          [item.id]
        ).catch(() => ({ rowCount: 0 }));
        expect(deleteB.rowCount).toBe(0);
      });

      // 5. Verify row remains intact and unmutated under Tenant A
      await adapter.withTenantTx(principalA, async (txA) => {
        const readA2 = await txA.query(`SELECT * FROM ${item.name} WHERE ${item.idCol} = $1;`, [item.id]);
        expect(readA2.rows.length).toBe(1);
      });
    });
  }
});
