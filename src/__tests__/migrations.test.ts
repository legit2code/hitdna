import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb, loadMigrations, loadSeedSql } from '@caim/db/migrator.js';

describe('P03 Database Migrations & Invariant Verification', () => {
  let db: any;

  beforeEach(() => {
    // Rehearse clean rebuild from empty database
    db = createTestDb({ applyMigrations: true, applySeed: false });
  });

  it('should load all ordered migrations successfully', () => {
    const migrations = loadMigrations();
    expect(migrations.length).toBeGreaterThanOrEqual(6);
    expect(migrations[0].filename).toContain('000001_p03_extensions_and_schemas');
    expect(migrations[1].filename).toContain('000002_p03_security_tenants_and_scopes');
    expect(migrations[2].filename).toContain('000003_p03_core_identity_and_registries');
    expect(migrations[3].filename).toContain('000004_p03_source_and_artifacts');
    expect(migrations[4].filename).toContain('000005_p03_ontology_and_version_registry');
    expect(migrations[5].filename).toContain('000006_p03_analysis_foundation');
  });

  it('should successfully apply reference seed data and verify baseline entities', () => {
    const seededDb = createTestDb({ applyMigrations: true, applySeed: true });

    const classifications = seededDb.public.many(`SELECT * FROM security.security_classifications ORDER BY rank ASC;`);
    expect(classifications).toHaveLength(4);
    expect(classifications.map((c: any) => c.code)).toEqual([
      'PUBLIC_METADATA',
      'INTERNAL',
      'SENSITIVE',
      'VAULT_RESTRICTED',
    ]);

    const platformScopes = seededDb.public.many(`SELECT * FROM security.access_scopes WHERE scope_type = 'PLATFORM';`);
    expect(platformScopes).toHaveLength(1);
    expect(platformScopes[0].tenant_id).toBeNull();

    const roles = seededDb.public.many(`SELECT * FROM security.roles ORDER BY role_key ASC;`);
    expect(roles.length).toBeGreaterThanOrEqual(5);

    const ontologyVersion = seededDb.public.one(`SELECT * FROM ontology.ontology_versions WHERE version_label = '2.0.1';`);
    expect(ontologyVersion.status).toBe('ACTIVE');

    const concepts = seededDb.public.many(`SELECT * FROM ontology.ontology_concepts;`);
    expect(concepts.length).toBeGreaterThanOrEqual(10);

    const activeRegistry = seededDb.public.many(`SELECT * FROM ops.version_registry WHERE status = 'ACTIVE';`);
    expect(activeRegistry.length).toBeGreaterThanOrEqual(3);
  });

  it('should enforce that AgentVersion strictly belongs to a CanonicalAgent via Foreign Key', () => {
    const fakeAgentId = '11111111-1111-1111-1111-111111111111';
    const versionId = '22222222-2222-2222-2222-222222222222';

    expect(() => {
      db.public.none(`
        INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint)
        VALUES ('${versionId}', '${fakeAgentId}', 'v1.0.0', 'sha256:fingerprint123');
      `);
    }).toThrow();

    // Create valid CanonicalAgent first
    const realAgentId = '33333333-3333-3333-3333-333333333333';
    db.public.none(`
      INSERT INTO core.canonical_agents (agent_id, canonical_name, status)
      VALUES ('${realAgentId}', 'Agent Alpha', 'ACTIVE');
    `);

    // Now version creation succeeds
    db.public.none(`
      INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint)
      VALUES ('${versionId}', '${realAgentId}', 'v1.0.0', 'sha256:fingerprint123');
    `);

    const savedVersion = db.public.one(`SELECT * FROM core.agent_versions WHERE agent_version_id = '${versionId}';`);
    expect(savedVersion.agent_id).toBe(realAgentId);

    // Duplicate content_fingerprint for the same agent must fail
    expect(() => {
      db.public.none(`
        INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint)
        VALUES ('44444444-4444-4444-4444-444444444444', '${realAgentId}', 'v1.0.1', 'sha256:fingerprint123');
      `);
    }).toThrow();
  });

  it('should enforce PLATFORM vs ORGANIZATION access scope invariants (Document 21)', () => {
    // 1. Valid PLATFORM scope with NULL tenant_id
    const platformScopeId = '00000000-0000-0000-0000-000000000001';
    db.public.none(`
      INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
      VALUES ('${platformScopeId}', 'PLATFORM', NULL);
    `);

    // Create tenant
    const tenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    db.public.none(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES ('${tenantId}', 'acme-corp', 'Acme Corporation', 'ACTIVE');
    `);

    // 2. Invalid PLATFORM scope with non-null tenant_id must fail check constraint
    expect(() => {
      db.public.none(`
        INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
        VALUES ('00000000-0000-0000-0000-000000000002', 'PLATFORM', '${tenantId}');
      `);
    }).toThrow();

    // 3. Invalid ORGANIZATION scope with null tenant_id must fail check constraint
    expect(() => {
      db.public.none(`
        INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
        VALUES ('00000000-0000-0000-0000-000000000003', 'ORGANIZATION', NULL);
      `);
    }).toThrow();

    // 4. Valid ORGANIZATION scope with valid tenant_id
    const orgScopeId = '00000000-0000-0000-0000-000000000004';
    db.public.none(`
      INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
      VALUES ('${orgScopeId}', 'ORGANIZATION', '${tenantId}');
    `);

    // 5. Exactly one PLATFORM scope invariant (duplicate PLATFORM scope must fail unique index)
    expect(() => {
      db.public.none(`
        INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
        VALUES ('00000000-0000-0000-0000-000000000005', 'PLATFORM', NULL);
      `);
    }).toThrow();

    // 6. Duplicate ORGANIZATION scope for same tenant must fail unique index
    expect(() => {
      db.public.none(`
        INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
        VALUES ('00000000-0000-0000-0000-000000000006', 'ORGANIZATION', '${tenantId}');
      `);
    }).toThrow();
  });

  it('should enforce AnalysisRun scope requirement and composite unique constraints', () => {
    // Setup agent, version, platform scope
    const agentId = '11111111-2222-3333-4444-555555555555';
    const versionId = '22222222-3333-4444-5555-666666666666';
    const scopeId = '00000000-0000-0000-0000-000000000001';

    db.public.none(`
      INSERT INTO core.canonical_agents (agent_id, canonical_name) VALUES ('${agentId}', 'Agent Analysis Target');
      INSERT INTO core.agent_versions (agent_version_id, agent_id, content_fingerprint) VALUES ('${versionId}', '${agentId}', 'sha256:abc');
      INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id) VALUES ('${scopeId}', 'PLATFORM', NULL);
    `);

    const runId = '99999999-9999-9999-9999-999999999999';
    db.public.none(`
      INSERT INTO analysis.analysis_runs (
        analysis_run_id, agent_version_id, scope_id, pipeline_version, caim_version, ontology_version, trigger_type, status
      ) VALUES (
        '${runId}', '${versionId}', '${scopeId}', '2.0.1', '2.0.1', '2.0.1', 'SCHEDULED', 'PENDING'
      );
    `);

    const run = db.public.one(`SELECT * FROM analysis.analysis_runs WHERE analysis_run_id = '${runId}';`);
    expect(run.agent_version_id).toBe(versionId);
    expect(run.scope_id).toBe(scopeId);

    // Analysis Stage Run with unique (analysis_run_id, engine_key)
    const stageId = '88888888-8888-8888-8888-888888888888';
    db.public.none(`
      INSERT INTO analysis.analysis_stage_runs (
        stage_run_id, analysis_run_id, engine_key, engine_version, status
      ) VALUES (
        '${stageId}', '${runId}', 'STATIC_AST', '2.0.1', 'PENDING'
      );
    `);

    // Duplicate stage engine key for the same analysis run must fail
    expect(() => {
      db.public.none(`
        INSERT INTO analysis.analysis_stage_runs (
          stage_run_id, analysis_run_id, engine_key, engine_version, status
        ) VALUES (
          '77777777-7777-7777-7777-777777777777', '${runId}', 'STATIC_AST', '2.0.1', 'PENDING'
        );
      `);
    }).toThrow();
  });

  it('should enforce source-scoped external aliases', () => {
    // Setup classification, agent, entity_ref, source_adapters
    const classId = '00000000-0000-0000-0000-000000000010';
    const agentId = 'aaaaaaaa-1111-2222-3333-444444444444';
    const refId = 'bbbbbbbb-1111-2222-3333-444444444444';
    const adapter1 = 'cccccccc-1111-2222-3333-444444444444';
    const adapter2 = 'dddddddd-1111-2222-3333-444444444444';

    db.public.none(`
      INSERT INTO security.security_classifications (security_classification_id, code, rank, description)
      VALUES ('${classId}', 'PUBLIC_METADATA', 0, 'Public metadata');
      
      INSERT INTO core.canonical_agents (agent_id, canonical_name) VALUES ('${agentId}', 'Alias Target Agent');

      INSERT INTO core.entity_refs (entity_ref_id, entity_kind, native_id, agent_id, security_classification_id)
      VALUES ('${refId}', 'CANONICAL_AGENT', '${agentId}', '${agentId}', '${classId}');

      INSERT INTO source.source_adapters (source_adapter_id, adapter_key, adapter_version, source_type)
      VALUES ('${adapter1}', 'github-scraper', '1.0.0', 'GIT');

      INSERT INTO source.source_adapters (source_adapter_id, adapter_key, adapter_version, source_type)
      VALUES ('${adapter2}', 'npm-registry', '1.0.0', 'PACKAGE_REGISTRY');
    `);

    // Insert alias for adapter 1
    db.public.none(`
      INSERT INTO core.external_aliases (external_alias_id, entity_ref_id, source_adapter_id, alias_type, alias_value)
      VALUES ('11111111-aaaa-bbbb-cccc-111111111111', '${refId}', '${adapter1}', 'REPO_NAME', 'org/cool-agent');
    `);

    // Same alias for adapter 2 is allowed (source-scoped)
    db.public.none(`
      INSERT INTO core.external_aliases (external_alias_id, entity_ref_id, source_adapter_id, alias_type, alias_value)
      VALUES ('22222222-aaaa-bbbb-cccc-222222222222', '${refId}', '${adapter2}', 'REPO_NAME', 'org/cool-agent');
    `);

    // Duplicate alias for same adapter 1 must fail
    expect(() => {
      db.public.none(`
        INSERT INTO core.external_aliases (external_alias_id, entity_ref_id, source_adapter_id, alias_type, alias_value)
        VALUES ('33333333-aaaa-bbbb-cccc-333333333333', '${refId}', '${adapter1}', 'REPO_NAME', 'org/cool-agent');
      `);
    }).toThrow();
  });

  it('should enforce version registry uniqueness and single active activation rules', () => {
    const reg1 = '11111111-0000-0000-0000-000000000001';
    db.public.none(`
      INSERT INTO ops.version_registry (version_registry_id, artifact_type, artifact_key, version, status, content_hash)
      VALUES ('${reg1}', 'ONTOLOGY', 'caim-standard', '1.0.0', 'DEPRECATED', 'sha256:hash1');
    `);

    const reg2 = '11111111-0000-0000-0000-000000000002';
    db.public.none(`
      INSERT INTO ops.version_registry (version_registry_id, artifact_type, artifact_key, version, status, content_hash)
      VALUES ('${reg2}', 'ONTOLOGY', 'caim-standard', '2.0.0', 'ACTIVE', 'sha256:hash2');
    `);

    // Duplicate version string for same artifact_type and key must fail
    expect(() => {
      db.public.none(`
        INSERT INTO ops.version_registry (version_registry_id, artifact_type, artifact_key, version, status, content_hash)
        VALUES ('11111111-0000-0000-0000-000000000003', 'ONTOLOGY', 'caim-standard', '2.0.0', 'DRAFT', 'sha256:hash3');
      `);
    }).toThrow();

    // Second ACTIVE version for same artifact_type and key must fail single active partial index
    expect(() => {
      db.public.none(`
        INSERT INTO ops.version_registry (version_registry_id, artifact_type, artifact_key, version, status, content_hash)
        VALUES ('11111111-0000-0000-0000-000000000004', 'ONTOLOGY', 'caim-standard', '2.0.1', 'ACTIVE', 'sha256:hash4');
      `);
    }).toThrow();
  });
});
