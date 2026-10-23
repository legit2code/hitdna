import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgresDatabaseAdapter } from '../../packages/db/src/postgres-adapter.ts';

const DATABASE_URL = process.env.DATABASE_URL;

describe.skipIf(!DATABASE_URL)('Database Roles & Non-Bypass Security Context (R05)', () => {
  let adapter: PostgresDatabaseAdapter;

  beforeAll(async () => {
    adapter = new PostgresDatabaseAdapter({
      connectionString: DATABASE_URL,
      applicationName: 'test-roles',
    });
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('caim_app role has NO BYPASSRLS and is NOT superuser', async () => {
    const res = await adapter.query(
      "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'caim_app';"
    );
    expect(res.rows.length).toBe(1);
    const role = res.rows[0];
    expect(role.rolname).toBe('caim_app');
    expect(role.rolsuper).toBe(false);
    expect(role.rolbypassrls).toBe(false);
    expect(role.rolcanlogin).toBe(false);
  });

  it('caim_system role has NO BYPASSRLS and is NOT superuser', async () => {
    const res = await adapter.query(
      "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'caim_system';"
    );
    expect(res.rows.length).toBe(1);
    const role = res.rows[0];
    expect(role.rolname).toBe('caim_system');
    expect(role.rolsuper).toBe(false);
    expect(role.rolbypassrls).toBe(false);
    expect(role.rolcanlogin).toBe(false);
  });

  it('caim_migrator role has NO BYPASSRLS and is NOT superuser', async () => {
    const res = await adapter.query(
      "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'caim_migrator';"
    );
    expect(res.rows.length).toBe(1);
    const role = res.rows[0];
    expect(role.rolname).toBe('caim_migrator');
    expect(role.rolsuper).toBe(false);
    expect(role.rolbypassrls).toBe(false);
    expect(role.rolcanlogin).toBe(false);
  });

  it('SELECT set_config(app.system_bypass, true, false) as caim_app changes nothing about visible rows', async () => {
    const tenantA = '00000000-0000-0000-0000-0000000000a1';
    const tenantB = '00000000-0000-0000-0000-0000000000b1';

    // Seed test tenants if not present
    await adapter.query(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES ($1, 'tenant-a-test', 'Tenant A', 'ACTIVE'), ($2, 'tenant-b-test', 'Tenant B', 'ACTIVE')
      ON CONFLICT (tenant_id) DO NOTHING;
    `, [tenantA, tenantB]);

    // Insert an isolated row under Tenant B
    const findingId = '00000000-0000-0000-0000-000000000fb1';
    await adapter.query(`
      INSERT INTO analysis.static_findings (
        finding_id, tenant_id, rule_id, severity, confidence, message, status
      ) VALUES ($1, $2, 'RULE-001', 'HIGH', 1.0, 'Secret tenant B finding', 'OPEN')
      ON CONFLICT (finding_id) DO NOTHING;
    `, [findingId, tenantB]);

    const principalA = {
      principal_id: 'usr-tenant-a',
      is_authenticated: true,
      tenant_id: tenantA,
      roles: ['user'],
    };

    // Run inside withTenantTx (SET LOCAL ROLE caim_app)
    await adapter.withTenantTx(principalA, async (tx) => {
      // 1. Initial query: Tenant A cannot see Tenant B's finding under fail-closed RLS
      const check1 = await tx.query(
        'SELECT * FROM analysis.static_findings WHERE finding_id = $1;',
        [findingId]
      );
      expect(check1.rows.length).toBe(0);

      // 2. Adversarial attempt: Set GUC app.system_bypass = 'true'
      await tx.query("SELECT set_config('app.system_bypass', 'true', false);");
      await tx.query("SELECT set_config('app.is_system_context', 'true', false);");

      // 3. Re-query: Must STILL be 0 rows because policies test pg_has_role(current_user, 'caim_system', 'member')
      // No GUC is permitted to grant privilege
      const check2 = await tx.query(
        'SELECT * FROM analysis.static_findings WHERE finding_id = $1;',
        [findingId]
      );
      expect(check2.rows.length).toBe(0);
    });
  });
});
