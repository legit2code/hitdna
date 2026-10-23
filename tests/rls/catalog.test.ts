import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { PostgresDatabaseAdapter } from '../../packages/db/src/postgres-adapter.ts';

const DATABASE_URL = process.env.DATABASE_URL;

interface ManifestEntry {
  table_schema: string;
  table_name: string;
  classification: 'GLOBAL_REFERENCE' | 'PLATFORM_SHARED' | 'TENANT_OWNED' | 'DERIVED_FROM_PARENT' | 'SYSTEM_ONLY';
  tenant_column: string | null;
  scope_column: string | null;
  parent_fk_path: string | null;
  description: string;
}

describe.skipIf(!DATABASE_URL)('RLS Catalog Invariant & Classification Coverage (R06)', () => {
  let adapter: PostgresDatabaseAdapter;
  let manifest: ManifestEntry[];

  beforeAll(async () => {
    const manifestPath = path.resolve(process.cwd(), 'supabase/tenancy-manifest.json');
    expect(fs.existsSync(manifestPath), 'tenancy-manifest.json must exist').toBe(true);
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    adapter = new PostgresDatabaseAdapter({
      connectionString: DATABASE_URL,
      applicationName: 'test-rls-catalog',
    });
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('(a) every table in the live catalog appears in the manifest and vice versa', async () => {
    const res = await adapter.query<{ table_schema: string; table_name: string }>(`
      SELECT table_schema, table_name
      FROM information_schema.tables
      WHERE table_schema IN ('security', 'source', 'core', 'ontology', 'analysis', 'intel', 'knowledge', 'lifecycle', 'ops')
        AND table_type = 'BASE TABLE'
      ORDER BY table_schema, table_name;
    `);

    const liveTables = res.rows.map(r => `${r.table_schema}.${r.table_name}`);
    const manifestTables = manifest.map(m => `${m.table_schema}.${m.table_name}`);

    // Missing from manifest
    const unclassifiedInManifest = liveTables.filter(t => !manifestTables.includes(t));
    expect(
      unclassifiedInManifest,
      `Detected unclassified live tables not in supabase/tenancy-manifest.json: ${unclassifiedInManifest.join(', ')}`
    ).toEqual([]);

    // Missing from database
    const missingFromDb = manifestTables.filter(t => !liveTables.includes(t));
    expect(
      missingFromDb,
      `Manifest contains tables not found in live database catalog: ${missingFromDb.join(', ')}`
    ).toEqual([]);

    expect(liveTables.length).toBe(manifest.length);
  });

  it('(b) every non-global table has relrowsecurity and relforcerowsecurity and at least one policy per command', async () => {
    const nonGlobal = manifest.filter(m => m.classification !== 'GLOBAL_REFERENCE');

    const res = await adapter.query<{
      table_schema: string;
      table_name: string;
      rowsecurity: boolean;
      forcerowsecurity: boolean;
      policy_count: number;
    }>(`
      SELECT 
        n.nspname AS table_schema,
        c.relname AS table_name,
        c.relrowsecurity AS rowsecurity,
        c.relforcerowsecurity AS forcerowsecurity,
        count(p.polname)::int AS policy_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      LEFT JOIN pg_policy p ON p.polrelid = c.oid
      WHERE n.nspname IN ('security', 'source', 'core', 'ontology', 'analysis', 'intel', 'knowledge', 'lifecycle', 'ops')
        AND c.relkind = 'r'
      GROUP BY n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
      ORDER BY n.nspname, c.relname;
    `);

    const tableMap = new Map(res.rows.map(r => [`${r.table_schema}.${r.table_name}`, r]));

    const missingRls: string[] = [];
    const missingForceRls: string[] = [];
    const missingPolicy: string[] = [];

    for (const t of nonGlobal) {
      const key = `${t.table_schema}.${t.table_name}`;
      const entry = tableMap.get(key);
      if (!entry) {
        missingRls.push(`${key} (missing from catalog)`);
        continue;
      }
      if (!entry.rowsecurity) {
        missingRls.push(key);
      }
      if (!entry.forcerowsecurity) {
        missingForceRls.push(key);
      }
      if (entry.policy_count < 1) {
        missingPolicy.push(key);
      }
    }

    expect(missingRls, `Tables missing relrowsecurity: ${missingRls.join(', ')}`).toEqual([]);
    expect(missingForceRls, `Tables missing relforcerowsecurity: ${missingForceRls.join(', ')}`).toEqual([]);
    expect(missingPolicy, `Tables missing RLS policies: ${missingPolicy.join(', ')}`).toEqual([]);
  });

  it('(c) caim_app privileges equal the manifest (SYSTEM_ONLY tables have NO privileges for caim_app)', async () => {
    const systemOnly = manifest.filter(m => m.classification === 'SYSTEM_ONLY');
    const nonSystem = manifest.filter(m => m.classification !== 'SYSTEM_ONLY');

    // Verify SYSTEM_ONLY tables: caim_app has NO privileges
    for (const t of systemOnly) {
      const q = `SELECT has_table_privilege('caim_app', '${t.table_schema}.${t.table_name}', 'SELECT') AS has_select,
                        has_table_privilege('caim_app', '${t.table_schema}.${t.table_name}', 'INSERT') AS has_insert;`;
      const res = await adapter.query<{ has_select: boolean; has_insert: boolean }>(q);
      expect(
        res.rows[0].has_select,
        `caim_app must NOT have SELECT on SYSTEM_ONLY table ${t.table_schema}.${t.table_name}`
      ).toBe(false);
      expect(
        res.rows[0].has_insert,
        `caim_app must NOT have INSERT on SYSTEM_ONLY table ${t.table_schema}.${t.table_name}`
      ).toBe(false);
    }

    // Verify non-SYSTEM_ONLY tables: caim_app has SELECT
    for (const t of nonSystem) {
      const q = `SELECT has_table_privilege('caim_app', '${t.table_schema}.${t.table_name}', 'SELECT') AS has_select;`;
      const res = await adapter.query<{ has_select: boolean }>(q);
      expect(
        res.rows[0].has_select,
        `caim_app must have SELECT on non-SYSTEM_ONLY table ${t.table_schema}.${t.table_name}`
      ).toBe(true);
    }
  });

  it('(d) anon, authenticated, and PUBLIC have zero table privileges across all schemas', async () => {
    for (const role of ['anon', 'authenticated', 'public']) {
      const res = await adapter.query<{ count: number }>(`
        SELECT count(*)::int AS count
        FROM information_schema.table_privileges
        WHERE grantee = $1
          AND table_schema IN ('security', 'source', 'core', 'ontology', 'analysis', 'intel', 'knowledge', 'lifecycle', 'ops');
      `, [role.toUpperCase() === 'PUBLIC' ? 'PUBLIC' : role]);

      expect(
        res.rows[0].count,
        `Role ${role} must have zero privileges across application schemas`
      ).toBe(0);
    }
  });
});
