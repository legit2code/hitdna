/**
 * Live PostgreSQL Catalog RLS Compliance Verification
 * Measures actual pg_class, pg_namespace, pg_policy, and pg_roles catalog records.
 * Never calculates compliance solely from manifest counts.
 */

import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

export interface CatalogTableCheck {
  schema: string;
  table: string;
  classification: string;
  relrowsecurity: boolean;
  relforcerowsecurity: boolean;
  policyCount: number;
  owner: string;
  hasAppPrivilege: boolean;
  isCompliant: boolean;
  issues: string[];
}

export async function verifyLiveCatalogRls(databaseUrl?: string): Promise<{
  isCompliant: boolean;
  totalTables: number;
  globalRefTables: number;
  mandatoryTables: number;
  rlsEnabledCount: number;
  rlsForcedCount: number;
  policiesVerifiedCount: number;
  unprotectedTables: string[];
  tableChecks: CatalogTableCheck[];
}> {
  const connectionString = databaseUrl || process.env.DATABASE_URL;
  if (!connectionString) {
    console.error('FATAL: DATABASE_URL is not set.');
    process.exit(1);
  }

  const client = new pg.Client({ connectionString });
  await client.connect();

  try {
    // 1. Verify application role attributes in pg_roles
    const appRoleRes = await client.query(`
      SELECT rolname, rolsuper, rolbypassrls
      FROM pg_roles
      WHERE rolname IN ('caim_app_user', 'authenticated')
      ORDER BY rolname;
    `);

    for (const r of appRoleRes.rows) {
      if (r.rolsuper) {
        console.error(`FATAL: Application role '${r.rolname}' has SUPERUSER enabled!`);
        process.exit(1);
      }
      if (r.rolbypassrls) {
        console.error(`FATAL: Application role '${r.rolname}' has BYPASSRLS enabled!`);
        process.exit(1);
      }
    }

    // 2. Load tenancy manifest as the baseline expectation
    const manifestPath = path.resolve(process.cwd(), 'supabase/tenancy-manifest.json');
    if (!fs.existsSync(manifestPath)) {
      console.error(`FATAL: Tenancy manifest not found at ${manifestPath}`);
      process.exit(1);
    }
    const manifest: Array<{
      table_schema: string;
      table_name: string;
      classification: string;
    }> = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    const globalRefTables = manifest.filter((t) => t.classification === 'GLOBAL_REFERENCE');
    const mandatoryTables = manifest.filter((t) => t.classification !== 'GLOBAL_REFERENCE');

    // 3. Query live PostgreSQL catalog for all user tables
    const catalogRes = await client.query(`
      SELECT 
        n.nspname AS table_schema,
        c.relname AS table_name,
        c.relrowsecurity,
        c.relforcerowsecurity,
        pg_get_userbyid(c.relowner) AS table_owner,
        (
          SELECT COUNT(*)::int
          FROM pg_policies p
          WHERE p.schemaname = n.nspname AND p.tablename = c.relname
        ) AS policy_count,
        CASE
          WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'caim_app_user')
            THEN has_table_privilege('caim_app_user', c.oid, 'SELECT')
          WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated')
            THEN has_table_privilege('authenticated', c.oid, 'SELECT')
          ELSE true
        END AS has_app_privilege
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind = 'r'
        AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      ORDER BY n.nspname, c.relname;
    `);

    const catalogMap = new Map<string, any>();
    for (const row of catalogRes.rows) {
      catalogMap.set(`${row.table_schema}.${row.table_name}`, row);
    }

    // 4. Measure compliance for each table
    const tableChecks: CatalogTableCheck[] = [];
    const unprotectedTables: string[] = [];
    let rlsEnabledCount = 0;
    let rlsForcedCount = 0;
    let policiesVerifiedCount = 0;
    let privilegesVerifiedCount = 0;

    for (const item of mandatoryTables) {
      const fullName = `${item.table_schema}.${item.table_name}`;
      const cat = catalogMap.get(fullName);
      const issues: string[] = [];

      if (!cat) {
        issues.push('MISSING_FROM_CATALOG: Table not found in PostgreSQL');
        unprotectedTables.push(fullName);
        tableChecks.push({
          schema: item.table_schema,
          table: item.table_name,
          classification: item.classification,
          relrowsecurity: false,
          relforcerowsecurity: false,
          policyCount: 0,
          owner: 'UNKNOWN',
          hasAppPrivilege: false,
          isCompliant: false,
          issues,
        });
        continue;
      }

      const rlsEnabled = Boolean(cat.relrowsecurity);
      const forceRls = Boolean(cat.relforcerowsecurity);
      const policyCount = Number(cat.policy_count || 0);
      const owner = String(cat.table_owner);
      const hasPrivilege = Boolean(cat.has_app_privilege);

      if (!rlsEnabled) {
        issues.push('ROW_SECURITY_DISABLED: relrowsecurity is false');
      } else {
        rlsEnabledCount++;
      }

      if (!forceRls) {
        issues.push('ROW_SECURITY_NOT_FORCED: relforcerowsecurity is false');
      } else {
        rlsForcedCount++;
      }

      if (policyCount === 0) {
        issues.push('ZERO_POLICIES: No security policies defined in pg_policies');
      } else {
        policiesVerifiedCount++;
      }

      if (owner === 'caim_app_user' || owner === 'authenticated') {
        issues.push(`UNPRIVILEGED_OWNER: Table is owned by application role '${owner}'`);
      }

      if (!hasPrivilege) {
        issues.push('MISSING_PRIVILEGE: Application role lacks effective SELECT privilege on table');
      } else {
        privilegesVerifiedCount++;
      }

      const isCompliant = issues.length === 0;
      if (!isCompliant) {
        unprotectedTables.push(fullName);
      }

      tableChecks.push({
        schema: item.table_schema,
        table: item.table_name,
        classification: item.classification,
        relrowsecurity: rlsEnabled,
        relforcerowsecurity: forceRls,
        policyCount,
        owner,
        hasAppPrivilege: hasPrivilege,
        isCompliant,
        issues,
      });
    }

    const enabledPct = mandatoryTables.length > 0
      ? ((rlsEnabledCount / mandatoryTables.length) * 100).toFixed(1)
      : '0.0';
    const forcedPct = mandatoryTables.length > 0
      ? ((rlsForcedCount / mandatoryTables.length) * 100).toFixed(1)
      : '0.0';
    const policiesPct = mandatoryTables.length > 0
      ? ((policiesVerifiedCount / mandatoryTables.length) * 100).toFixed(1)
      : '0.0';
    const privilegesPct = mandatoryTables.length > 0
      ? ((privilegesVerifiedCount / mandatoryTables.length) * 100).toFixed(1)
      : '0.0';

    console.log('================================================================================');
    console.log('         LIVE POSTGRESQL CATALOG RLS MEASUREMENT REPORT (MEASURED)              ');
    console.log('================================================================================');
    console.log(`Measured Database Engine:            PostgreSQL (Live Catalog Inspection)`);
    console.log(`Total Tables in Tenancy Manifest:    ${manifest.length}`);
    console.log(`Global Reference Tables (No RLS):    ${globalRefTables.length}`);
    console.log(`Mandatory Tenant-Scoped Tables:      ${mandatoryTables.length}`);
    console.log(`Catalog Measured Tables Present:     ${tableChecks.filter((t) => t.owner !== 'UNKNOWN').length}/${mandatoryTables.length}`);
    console.log(`Measured Tables with RLS ENABLED:    ${rlsEnabledCount}/${mandatoryTables.length} (${enabledPct}%)`);
    console.log(`Measured Tables with RLS FORCED:     ${rlsForcedCount}/${mandatoryTables.length} (${forcedPct}%)`);
    console.log(`Measured Tables with Active Policies: ${policiesVerifiedCount}/${mandatoryTables.length} (${policiesPct}%)`);
    console.log(`Measured Tables with App Privileges:  ${privilegesVerifiedCount}/${mandatoryTables.length} (${privilegesPct}%)`);
    console.log('--------------------------------------------------------------------------------');

    if (unprotectedTables.length > 0) {
      console.error(`RLS COMPLIANCE CHECK FAILED: ${unprotectedTables.length} tables lack full protection:`);
      for (const t of tableChecks.filter((c) => !c.isCompliant)) {
        console.error(`  - ${t.schema}.${t.table} [${t.classification}]: ${t.issues.join('; ')}`);
      }
      return {
        isCompliant: false,
        totalTables: manifest.length,
        globalRefTables: globalRefTables.length,
        mandatoryTables: mandatoryTables.length,
        rlsEnabledCount,
        rlsForcedCount,
        policiesVerifiedCount,
        unprotectedTables,
        tableChecks,
      };
    }

    console.log('CATALOG RLS INVARIANT VERIFICATION: PASSED (100% Measured Catalog Compliance)');
    console.log('================================================================================');

    return {
      isCompliant: true,
      totalTables: manifest.length,
      globalRefTables: globalRefTables.length,
      mandatoryTables: mandatoryTables.length,
      rlsEnabledCount,
      rlsForcedCount,
      policiesVerifiedCount,
      unprotectedTables: [],
      tableChecks,
    };
  } finally {
    await client.end().catch(() => {});
  }
}

// Run CLI directly if invoked as main
const isMain = process.argv[1] && (process.argv[1].endsWith('verify-catalog-rls.ts') || process.argv[1].endsWith('verify-catalog-rls.js'));
if (isMain) {
  verifyLiveCatalogRls()
    .then((result) => {
      if (!result.isCompliant) {
        process.exit(1);
      }
      process.exit(0);
    })
    .catch((err) => {
      console.error('Fatal error during catalog RLS verification:', err);
      process.exit(1);
    });
}
