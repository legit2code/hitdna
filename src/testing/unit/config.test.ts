/**
 * Unit Test Suite: Typed Configuration & Secrets Engine (PF-03)
 * Architecture Engine: PF-03 (Modules M01–M08)
 * Architecture Version: 5.0.0 | Phase: P02
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  getServerConfig,
  getPublicClientConfig,
  getPublicConfig,
  getWorkerConfig,
  getFeatureFlags,
  redactSecret,
  maskObjectSecrets,
  getProviderStatuses,
  getProviderFeatureFlagStates,
  validateEnvironment,
  validatePublicConfigSchema,
  validateServerConfigSchema,
  KNOWN_RESEARCH_PROVIDERS,
  MODEL_REGISTRY,
  METHODOLOGY_REGISTRY,
  JOB_CADENCE_REGISTRY,
} from '../../config/environment.ts';
import { PF03_ENGINE_DEFINITION } from '../../domain/foundation.ts';

describe('PF-03: Typed Configuration & Secrets Engine', () => {
  it('PF-03.M01: Public Client Configuration isolates client safely without secrets', () => {
    const publicConfig = getPublicClientConfig();
    assert.equal(publicConfig.appName, 'Hit DNA Music Intelligence');
    assert.equal(publicConfig.architectureVersion, '5.0.0');
    assert.equal(publicConfig.version, '1.0.0');
    assert.ok(['P02', 'P03'].includes(publicConfig.currentPhase));
    assert.equal(publicConfig.apiPrefix, '/api');

    // Test getPublicConfig alias
    const aliasConfig = getPublicConfig();
    assert.deepEqual(aliasConfig, publicConfig);

    // Validate schema
    const schemaValidation = validatePublicConfigSchema(publicConfig);
    assert.equal(schemaValidation.valid, true);
    assert.equal(schemaValidation.errors.length, 0);

    // Confirm no secrets or raw credentials present in public configuration
    const serialized = JSON.stringify(publicConfig);
    assert.equal(serialized.includes('secret'), false);
    assert.equal(serialized.includes('key'), false);
    assert.equal(serialized.includes('token'), false);

    // Negative schema test: object with secret field should be rejected
    const taintedConfig = { ...publicConfig, apiKey: 'leaked_key' };
    const taintedValidation = validatePublicConfigSchema(taintedConfig);
    assert.equal(taintedValidation.valid, false);
    assert.ok(taintedValidation.errors.some(e => e.includes('Secret field detected')));
  });

  it('PF-03.M02: Server Runtime Configuration validates port, host, and environment', () => {
    const serverConfig = getServerConfig();
    assert.ok(typeof serverConfig.port === 'number' && serverConfig.port > 0);
    assert.equal(serverConfig.host, '0.0.0.0');
    assert.ok(['development', 'production', 'test'].includes(serverConfig.nodeEnv));
    assert.ok(Array.isArray(serverConfig.corsAllowedOrigins));
    assert.ok(serverConfig.maxPayloadBytes >= 1024 * 1024);
  });

  it('PF-03.M03: Worker & Job Configuration returns valid concurrency and timeouts', () => {
    const workerConfig = getWorkerConfig();
    assert.ok(workerConfig.concurrency >= 1);
    assert.ok(workerConfig.pollingIntervalMs >= 500);
    assert.ok(workerConfig.maxRetries >= 1);
    assert.ok(workerConfig.jobTimeoutMs >= 5000);
    assert.ok(workerConfig.outboxBatchSize >= 1);
    assert.ok(workerConfig.deadLetterThreshold >= 1);
  });

  it('PF-03.M04: Provider Credentials & Secrets Vault defines known research providers', () => {
    assert.ok(Array.isArray(KNOWN_RESEARCH_PROVIDERS));
    assert.equal(KNOWN_RESEARCH_PROVIDERS.length, 5);

    const providerNames = KNOWN_RESEARCH_PROVIDERS.map(p => p.name);
    assert.ok(providerNames.includes('GEMINI_API'));
    assert.ok(providerNames.includes('SPOTIFY_API'));
    assert.ok(providerNames.includes('BILLBOARD_API'));
    assert.ok(providerNames.includes('GENIUS_API'));
    assert.ok(providerNames.includes('SOUNDCHARTS_API'));
  });

  it('PF-03.M05: Secret Redaction & Log Masking obscures keys and deep objects', () => {
    // Null / empty / placeholder redaction
    assert.equal(redactSecret(undefined), '[NOT_CONFIGURED]');
    assert.equal(redactSecret(null), '[NOT_CONFIGURED]');
    assert.equal(redactSecret(''), '[NOT_CONFIGURED]');
    assert.equal(redactSecret('   '), '[NOT_CONFIGURED]');
    assert.equal(redactSecret('MY_GEMINI_API_KEY'), '[NOT_CONFIGURED]');

    // Short secret redaction
    assert.equal(redactSecret('12345'), '***');
    assert.equal(redactSecret('secret'), '***');

    // Long secret redaction
    const longSecret = 'sk-live-9876543210abcdef';
    const redacted = redactSecret(longSecret);
    assert.equal(redacted, 'sk-...def');
    assert.equal(redacted.includes('9876543210'), false);

    // Deep object masking
    const unmaskedLog = {
      event: 'provider_dispatch',
      apiKey: 'secret_123456789',
      metadata: {
        token: 'auth_token_xyz999',
        user: 'system_worker',
        nested: {
          private_key: 'top_secret_pk_99',
          safe_value: 42,
        },
      },
      tags: ['inference', 'evidence'],
    };

    const masked = maskObjectSecrets(unmaskedLog);
    assert.equal(masked.apiKey, 'sec...789');
    assert.equal(masked.metadata.token, 'aut...999');
    assert.equal(masked.metadata.user, 'system_worker');
    assert.equal(masked.metadata.nested.private_key, 'top..._99');
    assert.equal(masked.metadata.nested.safe_value, 42);
    assert.deepEqual(masked.tags, ['inference', 'evidence']);
  });

  it('PF-03.M06: Feature Flags & Runtime Switches yields typed operational flags', () => {
    const flags = getFeatureFlags();
    assert.equal(typeof flags.enableContinuousResearch, 'boolean');
    assert.equal(typeof flags.enableHybridAnalytics, 'boolean');
    assert.equal(typeof flags.enableArtistSafetyGuard, 'boolean');
    assert.equal(typeof flags.enableAIGeneration, 'boolean');
    assert.equal(typeof flags.enableLiveStreaming, 'boolean');
    assert.equal(typeof flags.maintenanceMode, 'boolean');
    // Safety guard should default to true
    assert.equal(flags.enableArtistSafetyGuard, true);
  });

  it('PF-03.M07: Environment Validation & Typing detects anomalies without fatal crash', () => {
    const validResult = validateEnvironment();
    assert.equal(validResult.valid, true);
    assert.equal(validResult.errors.length, 0);

    // Test with simulated invalid PORT
    const prevPort = process.env.PORT;
    try {
      process.env.PORT = 'invalid_port_number';
      const invalidResult = validateEnvironment();
      assert.equal(invalidResult.valid, false);
      assert.ok(invalidResult.errors.length > 0);
    } finally {
      process.env.PORT = prevPort;
    }
  });

  it('PF-03.M08: Provider Health & Credential State Resolver adheres to Playbook 1 invariants', () => {
    const statuses = getProviderStatuses();
    assert.equal(statuses.length, 5);

    for (const record of statuses) {
      // Epistemic state rule: AVAILABLE requires live verified execution, which has not occurred in P02
      assert.notEqual(record.status, 'AVAILABLE', `Provider ${record.name} cannot be marked AVAILABLE without executed verification`);
      assert.equal(record.liveVerificationPerformed, false);
      assert.ok(['NOT_CONFIGURED', 'CONFIGURED_UNVERIFIED'].includes(record.status));
      assert.ok(Array.isArray(record.requiredKeys));
      assert.ok(typeof record.configuredKeysCount === 'number');
      assert.ok(typeof record.details === 'string');
    }

    // Test explicit typed provider feature states (ENABLED, DISABLED_MISSING_CREDENTIAL, DISABLED_BY_POLICY, DEGRADED)
    const featureStates = getProviderFeatureFlagStates();
    const validTypedStates = ['ENABLED', 'DISABLED_MISSING_CREDENTIAL', 'DISABLED_BY_POLICY', 'DEGRADED'];
    for (const provider of KNOWN_RESEARCH_PROVIDERS) {
      const stateObj = featureStates[provider.name];
      assert.ok(stateObj, `Provider ${provider.name} must have a feature state entry`);
      assert.ok(validTypedStates.includes(stateObj.state), `State ${stateObj.state} must be a valid ProviderFeatureState`);
      assert.ok(typeof stateObj.details === 'string');
    }
  });

  it('Versioned Registries: Models, Methodology, and Job Cadences are locked configuration', () => {
    assert.equal(MODEL_REGISTRY.DEFAULT_GEMINI_FLASH, 'gemini-2.5-flash');
    assert.equal(MODEL_REGISTRY.DEFAULT_GEMINI_PRO, 'gemini-2.5-pro');

    assert.equal(METHODOLOGY_REGISTRY.CANONICAL_ARCHITECTURE_VERSION, '5.0.0');
    assert.equal(METHODOLOGY_REGISTRY.PROMPT_PACK_VERSION, '6.0.0');
    assert.equal(METHODOLOGY_REGISTRY.HIT_DNA_SPECIFICATION_VERSION, '5.0.0');

    assert.equal(JOB_CADENCE_REGISTRY.RESEARCH_INGESTION_CRON, '0 */6 * * *');
    assert.ok(JOB_CADENCE_REGISTRY.CHART_SYNC_CADENCE_MS > 0);
  });

  it('Server Config Schema Validation validates server parameters strictly', () => {
    const serverConfig = getServerConfig();
    const validRes = validateServerConfigSchema(serverConfig);
    assert.equal(validRes.valid, true);
    assert.equal(validRes.errors.length, 0);

    const invalidRes = validateServerConfigSchema({ port: -1, host: '', nodeEnv: 'invalid' });
    assert.equal(invalidRes.valid, false);
    assert.ok(invalidRes.errors.length >= 2);
  });

  it('PF-03 Engine Definition has all 8 canonical modules', () => {
    assert.equal(PF03_ENGINE_DEFINITION.engineId, 'PF-03');
    assert.equal(PF03_ENGINE_DEFINITION.modules.length, 8);
    const moduleIds = PF03_ENGINE_DEFINITION.modules.map(m => m.moduleId);
    for (let i = 1; i <= 8; i++) {
      assert.ok(moduleIds.includes(`PF-03.M0${i}`));
    }
  });
});
