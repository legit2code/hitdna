/**
 * Unit Tests: Platform Foundation & Tooling (PF-02)
 * Phase: P01
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PF02_ENGINE_DEFINITION, WORKSPACE_BOUNDARIES } from '../../domain/foundation.ts';
import { healthService } from '../../services/healthService.ts';
import { redactSecret, getServerConfig, getPublicClientConfig } from '../../config/environment.ts';
import { MemoryFoundationRepository } from '../../repositories/foundationRepository.ts';
import { MemoryJobQueue } from '../../workers/jobContracts.ts';
import { TEST_FIXTURE_SYSTEM_HEALTH } from '../fixtures/testFixtures.ts';

describe('PF-02 Foundation & Tooling Unit Tests', () => {
  test('PF-02 Engine Definition conforms to canonical architecture v5.0.0', () => {
    assert.equal(PF02_ENGINE_DEFINITION.engineId, 'PF-02');
    assert.equal(PF02_ENGINE_DEFINITION.name, 'Repository & Tooling Foundation');
    assert.equal(PF02_ENGINE_DEFINITION.modules.length, 9);
    assert.deepEqual(PF02_ENGINE_DEFINITION.primaryBuildPhases, ['P01']);

    const moduleIds = PF02_ENGINE_DEFINITION.modules.map(m => m.moduleId);
    assert.ok(moduleIds.includes('PF-02.M01')); // React App Shell
    assert.ok(moduleIds.includes('PF-02.M02')); // Node Server Shell
    assert.ok(moduleIds.includes('PF-02.M03')); // Workspace Boundary Manager
    assert.ok(moduleIds.includes('PF-02.M04')); // TypeScript Strict Config
    assert.ok(moduleIds.includes('PF-02.M05')); // Lint/Format Tooling
    assert.ok(moduleIds.includes('PF-02.M06')); // Unit Test Harness
    assert.ok(moduleIds.includes('PF-02.M07')); // Integration Test Harness
    assert.ok(moduleIds.includes('PF-02.M08')); // E2E Harness
    assert.ok(moduleIds.includes('PF-02.M09')); // CI Baseline
  });

  test('Workspace Boundaries define clean separation of concerns', () => {
    assert.equal(WORKSPACE_BOUNDARIES.client, 'src/client');
    assert.equal(WORKSPACE_BOUNDARIES.server, 'src/server');
    assert.equal(WORKSPACE_BOUNDARIES.domain, 'src/domain');
    assert.equal(WORKSPACE_BOUNDARIES.repositories, 'src/repositories');
    assert.equal(WORKSPACE_BOUNDARIES.services, 'src/services');
    assert.equal(WORKSPACE_BOUNDARIES.workers, 'src/workers');
    assert.equal(WORKSPACE_BOUNDARIES.contracts, 'src/contracts');
    assert.equal(WORKSPACE_BOUNDARIES.config, 'src/config');
    assert.equal(WORKSPACE_BOUNDARIES.testing, 'src/testing');
    assert.equal(WORKSPACE_BOUNDARIES.docs, 'docs');
  });

  test('HealthService returns typed healthy state without requiring provider keys', () => {
    const health = healthService.getHealth();
    assert.equal(health.status, 'healthy');
    assert.equal(health.architectureVersion, '5.0.0');
    assert.equal(health.checks.server, true);
    assert.equal(health.checks.config, true);

    const readiness = healthService.getReadiness();
    assert.equal(readiness.ready, true);
    assert.ok(['PF-02', 'PF-03', 'PF-04'].includes(readiness.engineId));
    assert.equal(readiness.missingRequirements.length, 0);

    const diagnostics = healthService.getDiagnostics();
    assert.ok(['PF-02', 'PF-03', 'PF-04'].includes(diagnostics.engineId));
    assert.ok(diagnostics.moduleCoverageCount >= 9);
    assert.ok(diagnostics.runtimeNodeVersion.startsWith('v'));
  });

  test('Secret redaction prevents token leakage to diagnostics and client', () => {
    assert.equal(redactSecret(undefined), '[NOT_CONFIGURED]');
    assert.equal(redactSecret(''), '[NOT_CONFIGURED]');
    assert.equal(redactSecret('short'), '***');
    assert.equal(redactSecret('secret_api_key_value_12345'), 'sec...345');
  });

  test('Public client config never exposes secrets', () => {
    const clientConfig = getPublicClientConfig();
    assert.equal(clientConfig.architectureVersion, '5.0.0');
    assert.ok(['P01', 'P02', 'P03'].includes(clientConfig.currentPhase));
    assert.ok(!('geminiApiKey' in clientConfig));
  });

  test('MemoryFoundationRepository saves and retrieves health check snapshot', async () => {
    const repo = new MemoryFoundationRepository();
    const initial = await repo.getLastHealthCheck();
    assert.equal(initial, null);

    await repo.saveHealthCheck(TEST_FIXTURE_SYSTEM_HEALTH);
    const saved = await repo.getLastHealthCheck();
    assert.deepEqual(saved, TEST_FIXTURE_SYSTEM_HEALTH);
  });

  test('JobQueue enqueues background jobs with pending status', async () => {
    const queue = new MemoryJobQueue();
    const job = await queue.enqueue('SYSTEM_DIAGNOSTICS', { checkId: 'CHK-P01-01' });
    assert.ok(job.jobId.startsWith('job_'));
    assert.equal(job.status, 'PENDING');

    const fetched = await queue.getJob(job.jobId);
    assert.deepEqual(fetched, job);
  });

  test('Test Fixtures are strictly isolated and labeled TEST_FIXTURE', () => {
    assert.equal(TEST_FIXTURE_SYSTEM_HEALTH.TAG, 'TEST_FIXTURE');
  });
});
