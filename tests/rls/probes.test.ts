import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { PostgresDatabaseAdapter } from '../../packages/db/src/postgres-adapter.ts';

const DATABASE_URL = process.env.DATABASE_URL;

interface ManifestEntry {
  table_schema: string;
  table_name: string;
  classification: string;
  tenant_column: string | null;
  scope_column: string | null;
  parent_fk_path: string | null;
  description: string;
}

describe.skipIf(!DATABASE_URL)('Two-Session Multi-Tenant Negative RLS Probes (R06)', () => {
  let adapter: PostgresDatabaseAdapter;
  let tenantOwnedTables: ManifestEntry[];

  const tenantA = 'a0000000-0000-0000-0000-000000000001';
  const tenantB = 'b0000000-0000-0000-0000-000000000002';

  const principalA = {
    principal_id: 'usr-probe-tenant-a',
    is_authenticated: true,
    tenant_id: tenantA,
    roles: ['user'],
  };

  const principalB = {
    principal_id: 'usr-probe-tenant-b',
    is_authenticated: true,
    tenant_id: tenantB,
    roles: ['user'],
  };

  beforeAll(async () => {
    const manifestPath = path.resolve(process.cwd(), 'supabase/tenancy-manifest.json');
    const manifest: ManifestEntry[] = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    tenantOwnedTables = manifest.filter(m => m.classification === 'TENANT_OWNED');

    adapter = new PostgresDatabaseAdapter({
      connectionString: DATABASE_URL,
      applicationName: 'test-rls-probes',
    });

    // Seed test tenants if not present
    await adapter.query(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES ($1, 'probe-tenant-a', 'Probe Tenant A', 'ACTIVE'),
             ($2, 'probe-tenant-b', 'Probe Tenant B', 'ACTIVE')
      ON CONFLICT (tenant_id) DO NOTHING;
    `, [tenantA, tenantB]);
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('verifies that for each TENANT_OWNED table, Tenant B cannot read, update, or delete Tenant A rows', async () => {
    for (const t of tenantOwnedTables) {
      if (t.table_name === 'tenants') {
        // Test tenants table isolation
        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.tenants WHERE tenant_id = $1;',
            [tenantA]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.tenants SET display_name = 'Hacked' WHERE tenant_id = $1;",
            [tenantA]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.tenants WHERE tenant_id = $1;',
            [tenantA]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);
        });

        // Tenant B cannot insert row with Tenant A's tenant_id (WITH CHECK rejection)
        await adapter.withTenantTx(principalB, async (tx) => {
          await expect(
            tx.query(`
              INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
              VALUES ('00000000-0000-0000-0000-000000000099', 'spoofed-key', 'Spoofed', 'ACTIVE');
            `)
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'tenant_memberships') {
        const memId = 'a0000000-0000-0000-0000-000000000010';
        await adapter.query(`
          INSERT INTO security.tenant_memberships (tenant_membership_id, tenant_id, principal_id, role_id, status)
          VALUES ($1, $2, 'usr-a-member', (SELECT role_id FROM security.roles LIMIT 1), 'ACTIVE')
          ON CONFLICT (tenant_membership_id) DO NOTHING;
        `, [memId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.tenant_memberships WHERE tenant_membership_id = $1;',
            [memId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.tenant_memberships SET status = 'REVOKED' WHERE tenant_membership_id = $1;",
            [memId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);
        });
      } else if (t.table_name === 'queries') {
        const qId = 'a0000000-0000-0000-0000-000000000020';
        await adapter.query(`
          INSERT INTO knowledge.queries (
            query_id, principal_id, query_text_or_hash, security_classification_id, tenant_id
          ) VALUES (
            $1, 'usr-probe-tenant-a', 'Secret tenant A query',
            (SELECT security_classification_id FROM security.security_classifications LIMIT 1),
            $2
          ) ON CONFLICT (query_id) DO NOTHING;
        `, [qId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM knowledge.queries WHERE query_id = $1;',
            [qId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A query in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE knowledge.queries SET query_text_or_hash = 'Tampered' WHERE query_id = $1;",
            [qId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A query in ${t.table_name}`).toBe(0);
        });

        // Tenant B cannot insert with Tenant A's tenant_id (WITH CHECK rejection)
        await adapter.withTenantTx(principalB, async (tx) => {
          await expect(
            tx.query(`
              INSERT INTO knowledge.queries (
                query_id, principal_id, query_text_or_hash, security_classification_id, tenant_id
              ) VALUES (
                gen_random_uuid(), 'usr-probe-tenant-b', 'Spoof insert',
                (SELECT security_classification_id FROM security.security_classifications LIMIT 1),
                $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'principals') {
        const pId = 'usr-probe-tenant-a';
        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.principals WHERE principal_id = $1;',
            [pId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.principals SET email = 'hacked@test.com' WHERE principal_id = $1;",
            [pId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.principals WHERE principal_id = $1;',
            [pId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.principals (
                principal_id, email, hashed_password, roles, tenant_id
              ) VALUES (
                'usr-probe-spoof-p', 'spoof@test.com', 'hash', '{"user"}', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'query_sessions') {
        const sId = 'a0000000-0000-0000-0000-000000000030';
        await adapter.query(`
          INSERT INTO knowledge.query_sessions (query_session_id, principal_id, tenant_id)
          VALUES ($1, 'usr-probe-tenant-a', $2)
          ON CONFLICT (query_session_id) DO NOTHING;
        `, [sId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM knowledge.query_sessions WHERE query_session_id = $1;',
            [sId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE knowledge.query_sessions SET access_context_hash = 'tampered' WHERE query_session_id = $1;",
            [sId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM knowledge.query_sessions WHERE query_session_id = $1;',
            [sId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO knowledge.query_sessions (query_session_id, principal_id, tenant_id)
              VALUES (gen_random_uuid(), 'usr-probe-tenant-b', $1);
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'modification_workspaces') {
        const wId = 'a0000000-0000-0000-0000-000000000040';
        await adapter.query(`
          INSERT INTO lifecycle.modification_workspaces (
            modification_workspace_id, base_agent_version_id, created_by, status, tenant_id
          ) VALUES (
            $1, (SELECT agent_version_id FROM core.agent_versions LIMIT 1),
            'usr-probe-tenant-a', 'ACTIVE', $2
          ) ON CONFLICT (modification_workspace_id) DO NOTHING;
        `, [wId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM lifecycle.modification_workspaces WHERE modification_workspace_id = $1;',
            [wId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE lifecycle.modification_workspaces SET status = 'REVOKED' WHERE modification_workspace_id = $1;",
            [wId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM lifecycle.modification_workspaces WHERE modification_workspace_id = $1;',
            [wId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO lifecycle.modification_workspaces (
                modification_workspace_id, base_agent_version_id, created_by, status, tenant_id
              ) VALUES (
                gen_random_uuid(), (SELECT agent_version_id FROM core.agent_versions LIMIT 1),
                'usr-probe-tenant-b', 'ACTIVE', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'user_roles') {
        const urId = 'a0000000-0000-0000-0000-000000000050';
        await adapter.query(`
          INSERT INTO security.user_roles (
            user_role_id, principal_id, role_id, granted_by, tenant_id
          ) VALUES (
            $1, 'usr-probe-tenant-a', (SELECT role_id FROM security.roles LIMIT 1),
            'usr-probe-tenant-a', $2
          ) ON CONFLICT (user_role_id) DO NOTHING;
        `, [urId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.user_roles WHERE user_role_id = $1;',
            [urId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.user_roles SET granted_by = 'tampered' WHERE user_role_id = $1;",
            [urId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.user_roles WHERE user_role_id = $1;',
            [urId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.user_roles (
                user_role_id, principal_id, role_id, granted_by, tenant_id
              ) VALUES (
                gen_random_uuid(), 'usr-probe-tenant-b', (SELECT role_id FROM security.roles LIMIT 1),
                'usr-probe-tenant-b', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'access_grants') {
        const agId = 'a0000000-0000-0000-0000-000000000060';
        await adapter.query(`
          INSERT INTO security.access_grants (
            access_grant_id, principal_id, grant_type, target_scope, granted_by, tenant_id
          ) VALUES (
            $1, 'usr-probe-tenant-a', 'ROLE', 'DEFAULT', 'usr-probe-tenant-a', $2
          ) ON CONFLICT (access_grant_id) DO NOTHING;
        `, [agId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.access_grants WHERE access_grant_id = $1;',
            [agId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.access_grants SET target_scope = 'TAMPERED' WHERE access_grant_id = $1;",
            [agId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.access_grants WHERE access_grant_id = $1;',
            [agId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.access_grants (
                access_grant_id, principal_id, grant_type, target_scope, granted_by, tenant_id
              ) VALUES (
                gen_random_uuid(), 'usr-probe-tenant-b', 'ROLE', 'DEFAULT', 'usr-probe-tenant-b', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'restricted_capability_grants') {
        const rcId = 'a0000000-0000-0000-0000-000000000070';
        await adapter.query(`
          INSERT INTO security.restricted_capability_grants (
            grant_id, capability_key, principal_id, granted_by, justification, tenant_id
          ) VALUES (
            $1, 'cap.probe', 'usr-probe-tenant-a', 'usr-probe-tenant-a', 'testing', $2
          ) ON CONFLICT (grant_id) DO NOTHING;
        `, [rcId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.restricted_capability_grants WHERE grant_id = $1;',
            [rcId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.restricted_capability_grants SET justification = 'tampered' WHERE grant_id = $1;",
            [rcId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.restricted_capability_grants WHERE grant_id = $1;',
            [rcId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.restricted_capability_grants (
                grant_id, capability_key, principal_id, granted_by, justification, tenant_id
              ) VALUES (
                gen_random_uuid(), 'cap.probe', 'usr-probe-tenant-b', 'usr-probe-tenant-b', 'spoof', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'rate_limit_buckets') {
        const bKey = 'probe-rate-limit-a';
        await adapter.query(`
          INSERT INTO security.rate_limit_buckets (bucket_key, count, reset_at, tenant_id)
          VALUES ($1, 5, now() + interval '1 hour', $2)
          ON CONFLICT (bucket_key) DO NOTHING;
        `, [bKey, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.rate_limit_buckets WHERE bucket_key = $1;',
            [bKey]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.rate_limit_buckets SET count = 999 WHERE bucket_key = $1;",
            [bKey]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.rate_limit_buckets WHERE bucket_key = $1;',
            [bKey]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.rate_limit_buckets (bucket_key, count, reset_at, tenant_id)
              VALUES ('spoof-bucket', 1, now() + interval '1 hour', $1);
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'refresh_tokens') {
        const rtId = 'a0000000-0000-0000-0000-000000000080';
        await adapter.query(`
          INSERT INTO security.refresh_tokens (
            token_id, principal_id, token_hash, expires_at, tenant_id
          ) VALUES (
            $1, 'usr-probe-tenant-a', 'hash-a', now() + interval '1 day', $2
          ) ON CONFLICT (token_id) DO NOTHING;
        `, [rtId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.refresh_tokens WHERE token_id = $1;',
            [rtId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.refresh_tokens SET token_hash = 'tampered' WHERE token_id = $1;",
            [rtId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.refresh_tokens WHERE token_id = $1;',
            [rtId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.refresh_tokens (
                token_id, principal_id, token_hash, expires_at, tenant_id
              ) VALUES (
                gen_random_uuid(), 'usr-probe-tenant-b', 'hash-b', now() + interval '1 day', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      } else if (t.table_name === 'composer_generation_log') {
        const logId = 'a0000000-0000-0000-0000-000000000090';
        await adapter.query(`
          INSERT INTO security.composer_generation_log (
            log_id, principal_id, technique_category, request_text, status, tenant_id
          ) VALUES (
            $1, 'usr-probe-tenant-a', 'ANALYSIS', 'prompt a', 'SUCCESS', $2
          ) ON CONFLICT (log_id) DO NOTHING;
        `, [logId, tenantA]);

        await adapter.withTenantTx(principalB, async (tx) => {
          const res = await tx.query(
            'SELECT * FROM security.composer_generation_log WHERE log_id = $1;',
            [logId]
          );
          expect(res.rows.length, `Tenant B must not see Tenant A row in ${t.table_name}`).toBe(0);

          const updateRes = await tx.query(
            "UPDATE security.composer_generation_log SET request_text = 'tampered' WHERE log_id = $1;",
            [logId]
          );
          expect(updateRes.rowCount, `Tenant B must not update Tenant A row in ${t.table_name}`).toBe(0);

          const deleteRes = await tx.query(
            'DELETE FROM security.composer_generation_log WHERE log_id = $1;',
            [logId]
          );
          expect(deleteRes.rowCount, `Tenant B must not delete Tenant A row in ${t.table_name}`).toBe(0);

          await expect(
            tx.query(`
              INSERT INTO security.composer_generation_log (
                log_id, principal_id, technique_category, request_text, status, tenant_id
              ) VALUES (
                gen_random_uuid(), 'usr-probe-tenant-b', 'ANALYSIS', 'prompt b', 'SUCCESS', $1
              );
            `, [tenantA])
          ).rejects.toThrow();
        });
      }
    }
  });
});
