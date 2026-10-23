/**
 * Multi-Tenant Cross-Session RLS Negative Security Suite
 * Verifies that two distinct physical sessions with SET LOCAL app.current_tenant_id
 * completely isolate tenants against direct SELECT, JOIN, and UPDATE attacks.
 */

import { describe, it, expect } from 'vitest';
import { 
  queryCatalogRlsCompliance, 
  queryCatalogRlsComplianceAsync,
  runCrossSessionMultiTenantNegativeTest 
} from '@caim/db/migration-safety.js';

describe('Multi-Tenant Cross-Session RLS & Catalog Verification', () => {
  it('should query live system catalog pg_class.relrowsecurity joined against security.table_tenant_classifications', async () => {
    const reportSync = queryCatalogRlsCompliance();
    const reportAsync = await queryCatalogRlsComplianceAsync();

    expect(reportSync.isCompliant).toBe(true);
    expect(reportAsync.isCompliant).toBe(true);

    // Dynamic catalog assertions
    expect(reportSync.totalTablesChecked).toBeGreaterThanOrEqual(18);
    expect(reportSync.rlsEnabledTables).toBe(reportSync.totalTablesChecked);
    expect(reportSync.unprotectedTables).toEqual([]);

    // Every single multi-tenant table must have relrowsecurity=true and relforcerowsecurity=true
    for (const table of reportSync.tableDetails) {
      expect(table.rlsEnabled).toBe(true);
      expect(table.forceRls).toBe(true);
      expect(['TENANT_OWNED', 'TENANT_SHARED']).toContain(table.classification);
    }
  });

  it('should deny Tenant B session access to Tenant A data across separate connections via SELECT, JOIN, and UPDATE', async () => {
    const result = await runCrossSessionMultiTenantNegativeTest();

    expect(result.passed).toBe(true);

    // Direct SELECT probes
    expect(result.probes.directTenantSelectCount).toBe(0);
    expect(result.probes.directScopeSelectCount).toBe(0);
    expect(result.probes.directRunSelectCount).toBe(0);
    expect(result.probes.directFindingSelectCount).toBe(0);

    // JOIN probes
    expect(result.probes.crossTenantJoinCount).toBe(0);
    expect(result.probes.childTableJoinCount).toBe(0);

    // UPDATE mutation probes
    expect(result.probes.updateTenantRowCount).toBe(0);
    expect(result.probes.updateRunRowCount).toBe(0);
    expect(result.probes.updateFindingRowCount).toBe(0);

    // Integrity check
    expect(result.probes.tenantADataIntegrityPreserved).toBe(true);
  });
});
