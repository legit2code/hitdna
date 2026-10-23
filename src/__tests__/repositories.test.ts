import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.js';
import { PgMemDbRepositories } from '@caim/db/repositories.js';

describe('P03 Database Repositories Interface & Operations', () => {
  let db: any;
  let repos: PgMemDbRepositories;

  beforeEach(() => {
    db = createTestDb({ applyMigrations: true, applySeed: true });
    repos = new PgMemDbRepositories(db);
  });

  it('should create and retrieve CanonicalAgent and AgentVersions via repository', async () => {
    const agent = await repos.createAgent({
      agent_id: 'a0000000-0000-0000-0000-000000000001',
      canonical_name: 'SuperAgent',
      status: 'ACTIVE',
      identity_confidence: 0.98,
    });
    expect(agent.canonical_name).toBe('SuperAgent');

    const found = await repos.findAgentByName('superagent');
    expect(found).not.toBeNull();
    expect(found?.agent_id).toBe(agent.agent_id);

    const version = await repos.createAgentVersion({
      agent_version_id: 'b0000000-0000-0000-0000-000000000001',
      agent_id: agent.agent_id,
      version_label: '1.0.0',
      content_fingerprint: 'sha256:abc123def456',
    });
    expect(version.agent_id).toBe(agent.agent_id);

    const versions = await repos.getAgentVersions(agent.agent_id);
    expect(versions).toHaveLength(1);
    expect(versions[0].version_label).toBe('1.0.0');
  });

  it('should manage tenants, access scopes, and memberships', async () => {
    const platformScope = await repos.getPlatformScope();
    expect(platformScope).not.toBeNull();
    expect(platformScope?.scope_type).toBe('PLATFORM');

    const tenant = await repos.createTenant({
      tenant_id: 'c0000000-0000-0000-0000-000000000001',
      tenant_key: 'globex',
      display_name: 'Globex Corp',
      status: 'ACTIVE',
    });
    expect(tenant.tenant_key).toBe('globex');

    const orgScope = await repos.createAccessScope({
      scope_id: 'd0000000-0000-0000-0000-000000000001',
      scope_type: 'ORGANIZATION',
      tenant_id: tenant.tenant_id,
    });
    expect(orgScope.tenant_id).toBe(tenant.tenant_id);

    const fetchedOrgScope = await repos.getTenantScope(tenant.tenant_id);
    expect(fetchedOrgScope?.scope_id).toBe(orgScope.scope_id);
  });

  it('should register and retrieve version registry entries', async () => {
    const entry = await repos.getActiveVersion('ONTOLOGY', 'caim-standard');
    expect(entry).not.toBeNull();
    expect(entry?.version).toBe('2.0.1');

    const newAnalyzer = await repos.registerVersion({
      version_registry_id: 'e0000000-0000-0000-0000-000000000001',
      artifact_type: 'ANALYZER',
      artifact_key: 'ast-parser',
      version: '1.0.0',
      status: 'ACTIVE',
      content_hash: 'sha256:abcd',
      activated_at: new Date().toISOString(),
    });
    expect(newAnalyzer.artifact_key).toBe('ast-parser');

    const retrieved = await repos.getActiveVersion('ANALYZER', 'ast-parser');
    expect(retrieved?.version).toBe('1.0.0');
  });
});
