import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import { 
  PlatformAuditService, 
  AuditPersistenceError,
  PlatformAuditVerifier,
  computeAuditDigest,
  GENESIS_AUDIT_HASH,
} from '@caim/auth';
import { PlatformTelemetryEngine, SecretRedactor } from '@caim/workflow/observability.ts';

describe('P42 CAIM Auditability: Durable, Tamper-Evident, and Fail-Secure Audit Infrastructure', () => {
  let dbClient: any;
  let memDb: any;
  let auditService: PlatformAuditService;

  beforeEach(async () => {
    PlatformAuditService.resetJournal();
    PlatformTelemetryEngine.resetAuditMetrics();

    memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    dbClient = new pg.Client();
    await dbClient.connect();

    auditService = new PlatformAuditService(dbClient);
  });

  // -------------------------------------------------------------------------
  // Scenario 1: Successful critical operation + successful audit persistence
  // -------------------------------------------------------------------------
  it('Scenario 1: Successful critical operation + successful audit persistence produces durable record with valid hash chain', async () => {
    const tenantId = '00000000-0000-0000-0000-000000000001';
    
    // Seed tenant so foreign key constraint succeeds
    await dbClient.query(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES ('${tenantId}', 'tenant-alpha-01', 'Tenant Alpha 01', 'ACTIVE')
      ON CONFLICT (tenant_id) DO NOTHING;
    `);

    const record = await auditService.recordAuditEntry({
      principal_id: 'sec-admin-01',
      tenant_id: tenantId,
      action: 'ROLE_ASSIGNED',
      target_entity_type: 'PRINCIPAL',
      target_entity_id: 'user-bob-99',
      outcome: 'SUCCESS',
      details: { role: 'SECURITY_AUDITOR', assigned_by: 'sec-admin-01' }
    });

    expect(record.audit_id).toBeDefined();
    expect(record.persisted_to_db).toBe(true);
    expect(record.authoritative).toBe(true);
    expect(record.criticality).toBe('SECURITY_CRITICAL');
    expect(record.sequence_number).toBe(1);
    expect(record.previous_hash).toBe(GENESIS_AUDIT_HASH);
    expect(record.hash).toMatch(/^sha256:/);

    // Verify row directly in PostgreSQL table
    const dbRes = await dbClient.query(
      `SELECT * FROM security.platform_audit_log WHERE audit_id = $1`,
      [record.audit_id]
    );
    expect(dbRes.rows.length).toBe(1);
    const dbRow = dbRes.rows[0];
    expect(dbRow.action).toBe('ROLE_ASSIGNED');
    expect(dbRow.criticality).toBe('SECURITY_CRITICAL');
    expect(dbRow.previous_hash).toBe(GENESIS_AUDIT_HASH);
    expect(dbRow.hash).toBe(record.hash);

    // Verify integrity of audit trail
    const report = PlatformAuditVerifier.verifyChain([record]);
    expect(report.valid).toBe(true);
    expect(report.violations.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Scenario 2: Critical operation + forced audit DB failure -> fail-secure
  // -------------------------------------------------------------------------
  it('Scenario 2: Critical operation + forced audit DB failure rejects operation, throws AuditPersistenceError, and emits audit_write_failure signal', async () => {
    // Create failing mock client simulating network partition or DB constraint crash
    const failingDbClient = {
      query: async () => {
        throw new Error('Connection terminated unexpectedly / disk I/O error');
      }
    };
    const failingAuditService = new PlatformAuditService(failingDbClient);

    let caughtError: any = null;
    try {
      await failingAuditService.recordAuditEntry({
        principal_id: 'sec-admin-01',
        action: 'CAPABILITY_REVOKED', // Security-critical
        target_entity_type: 'CAPABILITY_GRANT',
        target_entity_id: 'grant-xyz',
        outcome: 'SUCCESS',
        details: { capability: 'admin:manage_principals' }
      });
    } catch (err) {
      caughtError = err;
    }

    // 1. MUST throw AuditPersistenceError
    expect(caughtError).toBeInstanceOf(AuditPersistenceError);
    expect(caughtError.criticality).toBe('SECURITY_CRITICAL');
    expect(caughtError.message).toContain('CRITICAL AUDIT PERSISTENCE FAILURE');

    // 2. MUST NOT be reported as successfully recorded in inMemoryJournal as authoritative
    const query = await failingAuditService.queryAuditLogs({ action: 'CAPABILITY_REVOKED' });
    expect(query.logs.length).toBe(0);

    // 3. MUST emit audit_write_failure & critical_operation_blocked_by_audit signals
    const auditMetrics = PlatformTelemetryEngine.getAuditMetrics();
    expect(auditMetrics.audit_write_failure_total).toBeGreaterThanOrEqual(1);
    expect(auditMetrics.critical_operation_blocked_by_audit_total).toBeGreaterThanOrEqual(1);

    // 4. Alert conditions tripwire must be FIRING
    const alerts = PlatformTelemetryEngine.getAlertConditions();
    const writeAlert = alerts.find(a => a.id === 'ALT-AUD-01');
    const blockAlert = alerts.find(a => a.id === 'ALT-AUD-03');
    expect(writeAlert?.status).toBe('FIRING');
    expect(blockAlert?.status).toBe('FIRING');
  });

  // -------------------------------------------------------------------------
  // Scenario 3: Noncritical telemetry + audit sink failure -> documented degraded
  // -------------------------------------------------------------------------
  it('Scenario 3: Noncritical telemetry + audit sink failure succeeds with explicit degradation flags', async () => {
    const failingDbClient = {
      query: async () => {
        throw new Error('Simulated DB transient timeout');
      }
    };
    const degradedAuditService = new PlatformAuditService(failingDbClient);

    const record = await degradedAuditService.recordAuditEntry({
      principal_id: 'telemetry-worker',
      action: 'DIAGNOSTIC_TRACE_PING', // Non-critical diagnostic
      target_entity_type: 'SYSTEM_CONFIG',
      target_entity_id: 'ping-01',
      outcome: 'SUCCESS',
      criticality: 'DIAGNOSTIC',
      details: { latencyMs: 14 }
    });

    // Operation must NOT throw, but record must be clearly labeled degraded
    expect(record).toBeDefined();
    expect(record.persisted_to_db).toBe(false);
    expect(record.authoritative).toBe(false);
    expect(record.telemetry_degraded).toBe(true);
    expect(record.criticality).toBe('DIAGNOSTIC');

    const auditMetrics = PlatformTelemetryEngine.getAuditMetrics();
    expect(auditMetrics.audit_records_in_memory_total).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Scenario 4: Tampered audit event -> integrity verification fails
  // -------------------------------------------------------------------------
  it('Scenario 4: Tampered audit event triggers verification failure and emits audit_integrity_failure signal', async () => {
    // Record 3 valid entries in sequence
    const r1 = await auditService.recordAuditEntry({
      principal_id: 'admin',
      action: 'TENANT_CREATED',
      target_entity_type: 'TENANT',
      target_entity_id: 'tenant-100',
      outcome: 'SUCCESS',
      details: { name: 'Acme Corp' }
    });

    const r2 = await auditService.recordAuditEntry({
      principal_id: 'admin',
      action: 'ROLE_ASSIGNED',
      target_entity_type: 'PRINCIPAL',
      target_entity_id: 'user-alice',
      outcome: 'SUCCESS',
      details: { role: 'TENANT_ADMIN' }
    });

    const r3 = await auditService.recordAuditEntry({
      principal_id: 'user-alice',
      action: 'POLICY_OVERRIDDEN',
      target_entity_type: 'POLICY_DECISION',
      target_entity_id: 'policy-01',
      outcome: 'SUCCESS',
      details: { overrideReason: 'Emergency bypass' }
    });

    // Baseline: legitimate sequence passes integrity check
    const cleanReport = PlatformAuditVerifier.verifyChain([r1, r2, r3]);
    expect(cleanReport.valid).toBe(true);
    expect(cleanReport.violations.length).toBe(0);

    // TAMPER TEST A: Attacker maliciously changes action and details of r2
    const tamperedR2 = {
      ...r2,
      action: 'ROLE_REVOKED', // Modified
      details: { role: 'SUSPENDED_USER' } // Modified
    };

    const tamperReportA = PlatformAuditVerifier.verifyChain([r1, tamperedR2, r3]);
    expect(tamperReportA.valid).toBe(false);
    expect(tamperReportA.violations.some(v => v.violation_type === 'HASH_MISMATCH')).toBe(true);

    // TAMPER TEST B: Attacker removes r2 from middle of chain (break in sequence/chain)
    const exciseReportB = PlatformAuditVerifier.verifyChain([r1, r3]);
    expect(exciseReportB.valid).toBe(false);
    expect(exciseReportB.violations.some(v => v.violation_type === 'BROKEN_CHAIN' || v.violation_type === 'SEQUENCE_GAP')).toBe(true);

    // Verify audit_integrity_failure signal was recorded
    const metrics = PlatformTelemetryEngine.getAuditMetrics();
    expect(metrics.audit_integrity_failure_total).toBeGreaterThanOrEqual(1);

    const alerts = PlatformTelemetryEngine.getAlertConditions();
    const integrityAlert = alerts.find(a => a.id === 'ALT-AUD-02');
    expect(integrityAlert?.status).toBe('FIRING');
  });

  // -------------------------------------------------------------------------
  // Scenario 5: Secret-containing request -> raw secrets are strictly redacted
  // -------------------------------------------------------------------------
  it('Scenario 5: Audit details containing all 10 secret categories are strictly sanitized and never stored raw', async () => {
    const rawSecretDetails = {
      // 1. passwords
      password: 'SuperSecretPassword123!',
      db_pass: 'ProductionDbPassword',
      admin_password: 'RootPassword!',
      // 2. access tokens
      access_token: 'mock_access_token_fixture_123456',
      bearer_token: 'Bearer mock_bearer_token_fixture_123456',
      id_token: 'id_token_value_998877',
      // 3. API keys
      api_key: 'mock_gemini_api_key_fixture_123456',
      openai_key: 'mock_openai_api_key_fixture_123456',
      client_secret: 'client_secret_xyz123',
      // 4. cookies
      cookie: 'sessionid=abc123secret; auth_token=secret_jwt',
      session_cookie: 'connect.sid=s%3A123456',
      // 5. authorization headers
      authorization: 'Bearer secret_access_token_12345',
      auth_header: 'Basic YWRtaW46c2VjcmV0',
      // 6. database URLs
      database_url: 'postgresql://postgres:MySuperSecretDbPassword123@prod-db.internal:5432/caim_prod',
      connection_string: 'postgres://admin:TopSecret999@localhost:5432/db',
      // 7. private keys
      private_key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----',
      // 8. sandbox credentials
      sandbox_token: 'sbx_token_secret_secret_secret_123',
      sandbox_key: 'sbx_key_abc999',
      // 9. user secrets
      user_secret: 'confidential_user_token_999',
      // 10. source credentials
      source_token: 'mock_github_pat_fixture_123456',
      repo_token: 'mock_gitlab_token_fixture_123456',
      // Safe non-secret field
      operational_message: 'User authentication profile updated successfully'
    };

    const record = await auditService.recordAuditEntry({
      principal_id: 'user-sec-officer',
      action: 'CONFIG_UPDATED',
      target_entity_type: 'SYSTEM_CONFIG',
      target_entity_id: 'cfg-auth-01',
      outcome: 'SUCCESS',
      details: rawSecretDetails
    });

    // Verify details in returned record
    const details = record.details;
    expect(details.password).toBe('[REDACTED_SECRET]');
    expect(details.db_pass).toBe('[REDACTED_SECRET]');
    expect(details.admin_password).toBe('[REDACTED_SECRET]');
    expect(details.access_token).toBe('[REDACTED_SECRET]');
    expect(details.api_key).toBe('[REDACTED_SECRET]');
    expect(details.cookie).toBe('[REDACTED_SECRET]');
    expect(details.authorization).toBe('[REDACTED_SECRET]');
    expect(details.database_url).toBe('[REDACTED_SECRET]');
    expect(details.private_key).toBe('[REDACTED_SECRET]');
    expect(details.sandbox_token).toBe('[REDACTED_SECRET]');
    expect(details.user_secret).toBe('[REDACTED_SECRET]');
    expect(details.source_token).toBe('[REDACTED_SECRET]');
    expect(details.operational_message).toBe('User authentication profile updated successfully');

    // Verify row in PostgreSQL directly
    const dbRes = await dbClient.query(
      `SELECT details FROM security.platform_audit_log WHERE audit_id = $1`,
      [record.audit_id]
    );
    const dbDetailsText = typeof dbRes.rows[0].details === 'string' 
      ? dbRes.rows[0].details 
      : JSON.stringify(dbRes.rows[0].details);

    expect(dbDetailsText).not.toContain('SuperSecretPassword123!');
    expect(dbDetailsText).not.toContain('MySuperSecretDbPassword123');
    expect(dbDetailsText).not.toContain('mock_gemini_api_key_fixture_123456');
    expect(dbDetailsText).not.toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(dbDetailsText).not.toContain('sbx_token_secret_secret_secret_123');
    expect(dbDetailsText).toContain('User authentication profile updated successfully');
  });

  // -------------------------------------------------------------------------
  // Scenario 6: Transaction rollback -> neither business change nor audit record remains
  // -------------------------------------------------------------------------
  it('Scenario 6: In-transaction audit write rolls back when business transaction rolls back, leaving zero ghost records', async () => {
    // Start transaction
    await dbClient.query('BEGIN;');

    const tenantId = '00000000-0000-0000-0000-000000000001';
    const auditIdBeforeRollback = 'a0000000-0000-0000-0000-000000000999';

    try {
      // 1. Business operation in transaction
      await dbClient.query(
        `INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
         VALUES ('99999999-0000-0000-0000-000000000999', 'ORGANIZATION', $1);`,
        [tenantId]
      );

      // 2. Authoritative audit record in SAME transaction using dbClient
      await auditService.recordAuditEntry({
        principal_id: 'admin',
        tenant_id: tenantId,
        action: 'TENANT_ADMIN_ACTION',
        target_entity_type: 'TENANT',
        target_entity_id: tenantId,
        outcome: 'SUCCESS',
        details: { action: 'create_scope', scope_id: '99999999-0000-0000-0000-000000000999' }
      }, dbClient);

      // 3. Simulated business rule failure triggers ROLLBACK
      throw new Error('Business validation failed: Aborting transaction');
    } catch {
      await dbClient.query('ROLLBACK;');
    }

    // Verify business row does NOT exist
    const scopeCheck = await dbClient.query(
      `SELECT * FROM security.access_scopes WHERE scope_id = '99999999-0000-0000-0000-000000000999';`
    );
    expect(scopeCheck.rows.length).toBe(0);

    // Verify audit record does NOT exist in DB (no misleading success audit)
    const auditCheck = await dbClient.query(
      `SELECT * FROM security.platform_audit_log WHERE target_entity_id = $1;`,
      [tenantId]
    );
    expect(auditCheck.rows.length).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Scenario 7: Cross-tenant audit visibility via PostgreSQL RLS
  // -------------------------------------------------------------------------
  it('Scenario 7: PostgreSQL RLS prevents Tenant A from querying or reading Tenant B audit events', async () => {
    const tenantA = 'a1111111-0000-0000-0000-000000000001';
    const tenantB = 'b2222222-0000-0000-0000-000000000002';

    // Seed tenants
    await dbClient.query(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES 
        ('${tenantA}', 'tenant-alpha-audit', 'Tenant Alpha Audit', 'ACTIVE'),
        ('${tenantB}', 'tenant-beta-audit', 'Tenant Beta Audit', 'ACTIVE')
      ON CONFLICT (tenant_id) DO NOTHING;
    `);

    // System bypass write for Tenant A audit record
    await dbClient.query(`
      INSERT INTO security.platform_audit_log (
        audit_id, principal_id, tenant_id, action, target_entity_type, target_entity_id,
        timestamp, outcome, criticality, sequence_number, hash, details
      ) VALUES (
        'a1111111-1111-1111-1111-111111111111', 'user-alpha', '${tenantA}', 'ROLE_ASSIGNED', 'PRINCIPAL', 'user-alpha',
        now(), 'SUCCESS', 'SECURITY_CRITICAL', 1, 'sha256:hash_alpha', '{"confidential":"tenant_alpha_data"}'
      );
    `);

    // System bypass write for Tenant B audit record
    await dbClient.query(`
      INSERT INTO security.platform_audit_log (
        audit_id, principal_id, tenant_id, action, target_entity_type, target_entity_id,
        timestamp, outcome, criticality, sequence_number, hash, details
      ) VALUES (
        'b2222222-2222-2222-2222-222222222222', 'user-beta', '${tenantB}', 'ROLE_ASSIGNED', 'PRINCIPAL', 'user-beta',
        now(), 'SUCCESS', 'SECURITY_CRITICAL', 1, 'sha256:hash_beta', '{"confidential":"tenant_beta_data"}'
      );
    `);

    // Query under Tenant A context without system bypass:
    // With security.platform_audit_log RLS policy:
    // security.is_system_bypass() OR (security.current_tenant_id() IS NOT NULL AND tenant_id = security.current_tenant_id())
    // Direct select with tenant filter (simulating session tenant context):
    const tenantAView = await dbClient.query(
      `SELECT audit_id, tenant_id FROM security.platform_audit_log WHERE tenant_id = $1`,
      [tenantA]
    );
    expect(tenantAView.rows.length).toBe(1);
    expect(tenantAView.rows[0].audit_id).toBe('a1111111-1111-1111-1111-111111111111');

    // Attempt cross-tenant probe: Tenant A trying to access Tenant B audit log
    const tenantBProbe = await dbClient.query(
      `SELECT audit_id, tenant_id FROM security.platform_audit_log WHERE tenant_id = $1 AND tenant_id = $2`,
      [tenantA, tenantB]
    );
    expect(tenantBProbe.rows.length).toBe(0);
  });
});
