import {
  FeatureFlagsSchema,
  FeatureFlags,
  ModelConfigSchema,
  ModelConfig,
  PublicConfigSchema,
  PublicConfig,
  ServerConfigSchema,
  ServerConfig,
  WorkerConfigSchema,
  WorkerConfig,
  OptionalProviders,
} from './schema.ts';

export class ConfigurationError extends Error {
  constructor(message: string, public readonly details?: unknown) {
    super(`[ConfigurationError] ${message}`);
    this.name = 'ConfigurationError';
  }
}

export type ProviderAdapterStatus =
  | { status: 'READY'; credentialPresent: true }
  | { status: 'DISABLED_MISSING_CREDENTIAL'; credentialPresent: false; reason: string };

function getEnv(key: string, fallback?: string): string | undefined {
  if (typeof process !== 'undefined' && process.env && process.env[key] !== undefined) {
    return process.env[key];
  }
  return fallback;
}

function parseBoolean(val: string | undefined, defaultValue: boolean): boolean {
  if (val === undefined || val === '') return defaultValue;
  return val.toLowerCase() === 'true' || val === '1';
}

/**
 * Loads feature flags safely from environment variables or defaults.
 */
export function getFeatureFlags(): FeatureFlags {
  const raw = {
    enableDynamicSandbox: parseBoolean(getEnv('FEATURE_DYNAMIC_SANDBOX'), true),
    enableEvasionDetection: parseBoolean(getEnv('FEATURE_EVASION_DETECTION'), true),
    enableTaintAnalysis: parseBoolean(getEnv('FEATURE_TAINT_ANALYSIS'), true),
    enableHybridRAG: parseBoolean(getEnv('FEATURE_HYBRID_RAG'), true),
    enableContinuousMonitoring: parseBoolean(getEnv('FEATURE_CONTINUOUS_MONITORING'), false),
    enableAutomatedRemediation: parseBoolean(getEnv('FEATURE_AUTOMATED_REMEDIATION'), false),
    enableModelCardAIBOM: parseBoolean(getEnv('FEATURE_MODEL_CARD_AIBOM'), true),
  };

  const parsed = FeatureFlagsSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid feature flag configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads model configuration.
 */
export function getModelConfig(): ModelConfig {
  const raw = {
    geminiModelDefault: getEnv('GEMINI_MODEL_DEFAULT', 'gemini-2.5-flash')!,
    geminiModelPro: getEnv('GEMINI_MODEL_PRO', 'gemini-2.5-pro')!,
    geminiEmbeddingModel: getEnv('GEMINI_MODEL_EMBEDDING', 'text-embedding-004')!,
    temperature: getEnv('MODEL_TEMPERATURE') ? parseFloat(getEnv('MODEL_TEMPERATURE')!) : 0.2,
    maxOutputTokens: getEnv('MODEL_MAX_OUTPUT_TOKENS') ? parseInt(getEnv('MODEL_MAX_OUTPUT_TOKENS')!, 10) : 8192,
  };

  const parsed = ModelConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid model configuration', parsed.error.format());
  }
  return parsed.data;
}

export type AppEnvironment = 'development' | 'test' | 'staging' | 'production';

export function getAppEnv(): AppEnvironment {
  const raw = getEnv('APP_ENV') || getEnv('NODE_ENV') || 'development';
  if (raw === 'production' || raw === 'staging' || raw === 'test' || raw === 'development') {
    return raw;
  }
  return 'development';
}

export function isProductionLike(env?: string): boolean {
  const current = env || getAppEnv();
  return current !== 'development' && current !== 'test';
}

/**
 * Loads sanitized public configuration suitable for browser consumption.
 * Guaranteed to NEVER include secrets, API keys, or private signing keys.
 */
export function getPublicConfig(): PublicConfig {
  const features = getFeatureFlags();
  const models = getModelConfig();

  const raw = {
    env: (getEnv('NODE_ENV') as any) || 'development',
    appEnv: getAppEnv(),
    appUrl: getEnv('APP_URL', 'http://localhost:3000')!,
    platformVersion: '2.0.1',
    baseline: 'V2.0.1 Controlled Implementation Baseline',
    apiPrefix: '/api',
    features,
    models: {
      defaultModel: models.geminiModelDefault,
      embeddingModel: models.geminiEmbeddingModel,
    },
  };

  const parsed = PublicConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid public configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads authoritative server-side configuration.
 */
export function getServerConfig(): ServerConfig {
  const features = getFeatureFlags();
  const models = getModelConfig();

  const raw = {
    env: (getEnv('NODE_ENV') as any) || 'development',
    appEnv: getAppEnv(),
    port: (() => {
      if (getEnv('APP_PORT')) return parseInt(getEnv('APP_PORT')!, 10);
      const portEnv = getEnv('PORT');
      const nginxPort = getEnv('NGINX_PORT');
      const defaultAppPort = getEnv('DEFAULT_APP_PORT');
      if (defaultAppPort && nginxPort && portEnv === nginxPort) {
        return parseInt(defaultAppPort, 10);
      }
      if (portEnv) return parseInt(portEnv, 10);
      if (getEnv('TEST_PORT')) return parseInt(getEnv('TEST_PORT')!, 10);
      if (defaultAppPort) return parseInt(defaultAppPort, 10);
      return 3000;
    })(),
    host: getEnv('HOST', '0.0.0.0')!,
    appUrl: getEnv('APP_URL', 'http://localhost:3000')!,
    corsOrigins: (() => {
      const raw = getEnv('CORS_ALLOWED_ORIGINS');
      if (raw) return raw.split(',').map((s) => s.trim()).filter(Boolean);
      return ['http://localhost:3000', 'http://127.0.0.1:3000'];
    })(),
    trustProxy: (() => {
      const raw = getEnv('TRUST_PROXY');
      if (raw === 'false') return false;
      if (raw === 'true') return true;
      if (raw && !isNaN(Number(raw))) return Number(raw);
      if (raw) return raw;
      return 1;
    })(),
    bodyLimit: getEnv('BODY_LIMIT', '256kb')!,
    ingestionBodyLimit: getEnv('INGESTION_BODY_LIMIT', '10mb')!,
    shutdownTimeoutMs: getEnv('SHUTDOWN_TIMEOUT_MS') ? parseInt(getEnv('SHUTDOWN_TIMEOUT_MS')!, 10) : 10000,
    geminiApiKey: getEnv('GEMINI_API_KEY'),
    auth: {
      jwtSecret: getEnv('JWT_SECRET'),
      serviceSecret: getEnv('SERVICE_TO_SERVICE_SECRET'),
      discoveryServiceToken: getEnv('CAIM_DISCOVERY_SERVICE_TOKEN'),
      serviceTenantScopes: (() => {
        const raw = getEnv('SERVICE_AUTHORIZED_TENANTS');
        if (raw) {
          try {
            return JSON.parse(raw);
          } catch {
            return undefined;
          }
        }
        return undefined;
      })(),
    },
    signing: {
      keyId: getEnv('SIGNING_KEY_ID', 'caim-v2-dev-key')!,
      algorithm: (getEnv('SIGNING_ALGORITHM') as any) || 'Ed25519',
      privateKey: getEnv('SIGNING_PRIVATE_KEY'),
      publicKey: getEnv('SIGNING_PUBLIC_KEY'),
    },
    providers: {
      githubToken: getEnv('GITHUB_TOKEN'),
      huggingfaceApiKey: getEnv('HUGGINGFACE_API_KEY'),
      e2bApiKey: getEnv('E2B_API_KEY'),
      sentryDsn: getEnv('SENTRY_DSN'),
      supabaseServiceKey: getEnv('SUPABASE_SERVICE_ROLE_KEY'),
      supabaseUrl: getEnv('SUPABASE_URL'),
    },
    features,
    models,
  };

  const parsed = ServerConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid server configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads worker configuration for a specific worker domain.
 */
export function getWorkerConfig(workerDomain: string): WorkerConfig {
  const raw = {
    workerDomain,
    concurrency: getEnv('WORKER_CONCURRENCY') ? parseInt(getEnv('WORKER_CONCURRENCY')!, 10) : 4,
    heartbeatIntervalMs: 10000,
    taskTimeoutMs: 300000,
    sandboxMemoryLimitMb: 1024,
    isolatedProcess: true,
    geminiApiKey: getEnv('GEMINI_API_KEY'),
    providers: {
      githubToken: getEnv('GITHUB_TOKEN'),
      huggingfaceApiKey: getEnv('HUGGINGFACE_API_KEY'),
      e2bApiKey: getEnv('E2B_API_KEY'),
      sentryDsn: getEnv('SENTRY_DSN'),
      supabaseServiceKey: getEnv('SUPABASE_SERVICE_ROLE_KEY'),
      supabaseUrl: getEnv('SUPABASE_URL'),
    },
  };

  const parsed = WorkerConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError(`Invalid worker configuration for ${workerDomain}`, parsed.error.format());
  }
  return parsed.data;
}

/**
 * Checks status of optional external provider adapters without throwing or halting startup.
 */
export function getOptionalProviderStatus(provider: keyof OptionalProviders): ProviderAdapterStatus {
  const serverConfig = getServerConfig();
  const credential = serverConfig.providers[provider];

  if (credential && credential.trim().length > 0) {
    return { status: 'READY', credentialPresent: true };
  }

  return {
    status: 'DISABLED_MISSING_CREDENTIAL',
    credentialPresent: false,
    reason: `Optional provider '${String(provider)}' is inactive because credentials are not configured in environment.`,
  };
}
