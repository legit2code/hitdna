import { describe, it, expect } from 'vitest';
import {
  getPublicConfig,
  getServerConfig,
  getWorkerConfig,
  getOptionalProviderStatus,
  redactSecret,
  redactObject,
  PublicConfigSchema,
  ServerConfigSchema,
} from '@caim/config';

describe('P02: Typed Configuration & Secret Boundaries', () => {
  it('should guarantee public config NEVER contains server-only secrets or keys', () => {
    const publicConfig = getPublicConfig();
    const serialized = JSON.stringify(publicConfig);

    // Assert schema validation
    expect(PublicConfigSchema.safeParse(publicConfig).success).toBe(true);

    // Negative assertions for forbidden secret terms
    expect(serialized).not.toContain('geminiApiKey');
    expect(serialized).not.toContain('privateKey');
    expect(serialized).not.toContain('githubToken');
    expect(serialized).not.toContain('huggingfaceApiKey');
    expect(serialized).not.toContain('e2bApiKey');
    expect(serialized).not.toContain('supabaseServiceKey');
  });

  it('should load server configuration with typed models and feature flags', () => {
    const serverConfig = getServerConfig();
    expect(ServerConfigSchema.safeParse(serverConfig).success).toBe(true);
    expect(serverConfig.port).toBe(3000);
    expect(serverConfig.host).toBe('0.0.0.0');
    expect(serverConfig.models.geminiModelDefault).toBeDefined();
    expect(typeof serverConfig.features.enableDynamicSandbox).toBe('boolean');
  });

  it('should return DISABLED_MISSING_CREDENTIAL for absent optional provider adapters without crashing', () => {
    const status = getOptionalProviderStatus('e2bApiKey');
    if (!process.env.E2B_API_KEY) {
      expect(status.status).toBe('DISABLED_MISSING_CREDENTIAL');
      expect(status.credentialPresent).toBe(false);
      if (status.status === 'DISABLED_MISSING_CREDENTIAL') {
        expect(status.reason).toContain('e2bApiKey');
      }
    } else {
      expect(status.status).toBe('READY');
      expect(status.credentialPresent).toBe(true);
    }
  });

  it('should load worker configuration isolated to worker domain', () => {
    const workerConfig = getWorkerConfig('static-analysis');
    expect(workerConfig.workerDomain).toBe('static-analysis');
    expect(workerConfig.isolatedProcess).toBe(true);
    expect(workerConfig.concurrency).toBeGreaterThan(0);
  });

  it('should properly redact sensitive strings and objects', () => {
    const rawSecret = 'AIzaSySecretTokenForTesting12345';
    const redacted = redactSecret(rawSecret);
    expect(redacted).toContain('[REDACTED]');
    expect(redacted).not.toBe(rawSecret);

    const testObject = {
      apiKey: 'secret_value_12345',
      clientToken: 'token_67890',
      publicName: 'CAIM Platform',
      nested: {
        privateKey: 'very_secret_key_value',
        version: '2.0.1',
      },
    };

    const sanitized = redactObject(testObject);
    expect(sanitized.apiKey).toContain('[REDACTED]');
    expect(sanitized.clientToken).toContain('[REDACTED]');
    expect(sanitized.publicName).toBe('CAIM Platform');
    expect(sanitized.nested.privateKey).toContain('[REDACTED]');
    expect(sanitized.nested.version).toBe('2.0.1');
  });
});
