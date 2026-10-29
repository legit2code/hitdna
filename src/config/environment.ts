/**
 * Typed Configuration & Secrets Engine Boundary (PF-03)
 * Architecture Engine: PF-03 (Modules M01–M08)
 * Architecture Version: 5.0.0 | Phase: P02
 *
 * Centralizes public, server, worker configuration, provider credentials,
 * feature flags, and secrets redaction with zero client-side leakage.
 */

export type NodeEnvironment = 'development' | 'production' | 'test';

export type ProviderOperationalState =
  | 'NOT_CONFIGURED'
  | 'CONFIGURED_UNVERIFIED'
  | 'AVAILABLE'
  | 'RATE_LIMITED'
  | 'ERROR'
  | 'POLICY_DISABLED';

export type ProviderFeatureState =
  | 'ENABLED'
  | 'DISABLED_MISSING_CREDENTIAL'
  | 'DISABLED_BY_POLICY'
  | 'DEGRADED';

/**
 * Versioned Model Registry
 */
export const MODEL_REGISTRY = {
  DEFAULT_GEMINI_FLASH: 'gemini-2.5-flash',
  DEFAULT_GEMINI_PRO: 'gemini-2.5-pro',
  EMBEDDINGS_MODEL: 'text-embedding-004',
} as const;

/**
 * Versioned Methodology Registry
 */
export const METHODOLOGY_REGISTRY = {
  CANONICAL_ARCHITECTURE_VERSION: '5.0.0',
  PROMPT_PACK_VERSION: '6.0.0',
  HIT_DNA_SPECIFICATION_VERSION: '5.0.0',
  STATISTICAL_CONFIDENCE_THRESHOLD: 0.95,
} as const;

/**
 * Versioned Job Cadence & Scheduling Registry
 */
export const JOB_CADENCE_REGISTRY = {
  RESEARCH_INGESTION_CRON: '0 */6 * * *',
  CHART_SYNC_CADENCE_MS: 3600000, // 1 hour
  AUDIO_ANALYSIS_BATCH_MS: 300000, // 5 min
  HEALTH_CHECK_INTERVAL_MS: 10000, // 10 sec
  POLL_INTERVAL_MS: 5000,
} as const;

export interface ServerConfig {
  port: number;
  host: string;
  nodeEnv: NodeEnvironment;
  appUrl: string;
  geminiApiKeyConfigured: boolean;
  corsAllowedOrigins: string[];
  maxPayloadBytes: number;
}

export interface PublicClientConfig {
  appName: string;
  version: string;
  architectureVersion: string;
  currentPhase: string;
  appUrl: string;
  apiPrefix: string;
}

export interface WorkerConfig {
  concurrency: number;
  pollingIntervalMs: number;
  maxRetries: number;
  jobTimeoutMs: number;
  outboxBatchSize: number;
  deadLetterThreshold: number;
}

export interface FeatureFlagsConfig {
  enableContinuousResearch: boolean;
  enableHybridAnalytics: boolean;
  enableArtistSafetyGuard: boolean;
  enableAIGeneration: boolean;
  enableLiveStreaming: boolean;
  maintenanceMode: boolean;
}

export interface ProviderDefinition {
  name: string;
  category: 'INFERENCE' | 'METADATA' | 'CHARTS' | 'LYRICS' | 'AUDIO';
  requiredEnvKeys: string[];
  optionalEnvKeys?: string[];
  docsUrl?: string;
}

export interface ProviderStatusRecord {
  name: string;
  category: string;
  status: ProviderOperationalState;
  requiredKeys: string[];
  configuredKeysCount: number;
  missingKeys: string[];
  liveVerificationPerformed: boolean;
  lastVerifiedAt: string | null;
  details: string;
}

export const KNOWN_RESEARCH_PROVIDERS: ProviderDefinition[] = [
  {
    name: 'GEMINI_API',
    category: 'INFERENCE',
    requiredEnvKeys: ['GEMINI_API_KEY'],
  },
  {
    name: 'SPOTIFY_API',
    category: 'METADATA',
    requiredEnvKeys: ['SPOTIFY_CLIENT_ID', 'SPOTIFY_CLIENT_SECRET'],
  },
  {
    name: 'BILLBOARD_API',
    category: 'CHARTS',
    requiredEnvKeys: ['BILLBOARD_API_KEY'],
  },
  {
    name: 'GENIUS_API',
    category: 'LYRICS',
    requiredEnvKeys: ['GENIUS_API_KEY'],
  },
  {
    name: 'SOUNDCHARTS_API',
    category: 'CHARTS',
    requiredEnvKeys: ['SOUNDCHARTS_APP_ID', 'SOUNDCHARTS_API_KEY'],
  },
];

/**
 * Returns safe server-side configuration.
 * Never leaks raw secrets directly.
 */
export function getServerConfig(): ServerConfig {
  const port = parseInt(process.env.PORT || '3000', 10);
  const host = '0.0.0.0';
  const nodeEnv = (process.env.NODE_ENV as NodeEnvironment) || 'development';
  const appUrl = process.env.APP_URL || `http://localhost:${port}`;
  const geminiApiKey = process.env.GEMINI_API_KEY;
  const geminiApiKeyConfigured = Boolean(
    geminiApiKey &&
    geminiApiKey.trim().length > 0 &&
    geminiApiKey !== 'MY_GEMINI_API_KEY'
  );

  return {
    port,
    host,
    nodeEnv,
    appUrl,
    geminiApiKeyConfigured,
    corsAllowedOrigins: [appUrl, `http://localhost:${port}`],
    maxPayloadBytes: 10 * 1024 * 1024, // 10MB
  };
}

/**
 * Returns strictly sanitized, safe public configuration.
 * Guaranteed zero secret exposure to client runtime.
 */
export function getPublicClientConfig(): PublicClientConfig {
  const port = parseInt(process.env.PORT || '3000', 10);
  const fallbackUrl = `http://localhost:${port}`;
  const resolvedAppUrl = typeof window !== 'undefined'
    ? window.location.origin
    : (process.env.APP_URL || fallbackUrl);

  return {
    appName: 'Hit DNA Music Intelligence',
    version: '1.0.0',
    architectureVersion: '5.0.0',
    currentPhase: 'P03',
    appUrl: resolvedAppUrl,
    apiPrefix: '/api',
  };
}

/**
 * Direct canonical alias for getPublicClientConfig
 * Strictly guaranteed to never contain server or provider secrets.
 */
export const getPublicConfig = getPublicClientConfig;

/**
 * Returns background worker runtime configuration.
 */
export function getWorkerConfig(): WorkerConfig {
  return {
    concurrency: parseInt(process.env.WORKER_CONCURRENCY || '4', 10),
    pollingIntervalMs: parseInt(process.env.WORKER_POLL_INTERVAL_MS || '5000', 10),
    maxRetries: parseInt(process.env.WORKER_MAX_RETRIES || '3', 10),
    jobTimeoutMs: parseInt(process.env.WORKER_JOB_TIMEOUT_MS || '60000', 10),
    outboxBatchSize: parseInt(process.env.OUTBOX_BATCH_SIZE || '50', 10),
    deadLetterThreshold: parseInt(process.env.DEAD_LETTER_THRESHOLD || '5', 10),
  };
}

/**
 * Returns feature flags with defaults and environment overrides.
 */
export function getFeatureFlags(): FeatureFlagsConfig {
  return {
    enableContinuousResearch: process.env.FEATURE_CONTINUOUS_RESEARCH === 'true',
    enableHybridAnalytics: process.env.FEATURE_HYBRID_ANALYTICS !== 'false',
    enableArtistSafetyGuard: process.env.FEATURE_ARTIST_SAFETY_GUARD !== 'false', // Default true
    enableAIGeneration: process.env.FEATURE_AI_GENERATION === 'true',
    enableLiveStreaming: process.env.FEATURE_LIVE_STREAMING === 'true',
    maintenanceMode: process.env.FEATURE_MAINTENANCE_MODE === 'true',
  };
}

/**
 * Redacts sensitive tokens from diagnostic and logging outputs.
 * Follows strict security masking rules.
 */
export function redactSecret(value?: string | null): string {
  if (!value || typeof value !== 'string') return '[NOT_CONFIGURED]';
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed === 'MY_GEMINI_API_KEY') return '[NOT_CONFIGURED]';
  if (trimmed.length <= 6) return '***';
  return `${trimmed.slice(0, 3)}...${trimmed.slice(-3)}`;
}

/**
 * Deep masks secrets in objects/arrays for logging, diagnostics, and API output.
 */
export function maskObjectSecrets<T>(data: T): T {
  if (data === null || data === undefined) return data;

  if (typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => maskObjectSecrets(item)) as unknown as T;
  }

  const maskedObj: Record<string, unknown> = {};
  const secretKeyRegex = /(api_?key|secret|token|password|auth|authorization|credential|cookie|private_?key)/i;

  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    if (secretKeyRegex.test(key)) {
      maskedObj[key] = typeof value === 'string' ? redactSecret(value) : '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      maskedObj[key] = maskObjectSecrets(value);
    } else {
      maskedObj[key] = value;
    }
  }

  return maskedObj as T;
}

/**
 * Evaluates provider health and configuration states under v6 Playbook 1 rules:
 * - Missing keys => NOT_CONFIGURED
 * - Configured keys without live verification => CONFIGURED_UNVERIFIED
 * - AVAILABLE strictly requires a real executed provider-specific verification result
 */
export function getProviderStatuses(): ProviderStatusRecord[] {
  return KNOWN_RESEARCH_PROVIDERS.map((provider) => {
    const missingKeys: string[] = [];
    let configuredCount = 0;

    for (const key of provider.requiredEnvKeys) {
      const val = process.env[key];
      if (val && val.trim().length > 0 && !val.startsWith('MY_')) {
        configuredCount++;
      } else {
        missingKeys.push(key);
      }
    }

    let status: ProviderOperationalState;
    let details: string;

    if (configuredCount === 0) {
      status = 'NOT_CONFIGURED';
      details = `Missing required credentials [${provider.requiredEnvKeys.join(', ')}]`;
    } else if (missingKeys.length > 0) {
      status = 'CONFIGURED_UNVERIFIED';
      details = `Partially configured (${configuredCount}/${provider.requiredEnvKeys.length}). Missing: [${missingKeys.join(', ')}]`;
    } else {
      // All keys present, but live external verification has not been executed in this phase
      status = 'CONFIGURED_UNVERIFIED';
      details = `Credentials configured (${configuredCount}/${provider.requiredEnvKeys.length}); awaiting phase provider live verification`;
    }

    return {
      name: provider.name,
      category: provider.category,
      status,
      requiredKeys: provider.requiredEnvKeys,
      configuredKeysCount: configuredCount,
      missingKeys,
      liveVerificationPerformed: false,
      lastVerifiedAt: null,
      details,
    };
  });
}

/**
 * Validates environment integrity on startup without throwing unhandled exceptions.
 */
export function validateEnvironment(): { valid: boolean; warnings: string[]; errors: string[] } {
  const warnings: string[] = [];
  const errors: string[] = [];

  const port = parseInt(process.env.PORT || '3000', 10);
  if (isNaN(port) || port <= 0 || port > 65535) {
    errors.push(`Invalid PORT configuration: "${process.env.PORT}". Must be between 1 and 65535.`);
  }

  const nodeEnv = process.env.NODE_ENV;
  if (nodeEnv && !['development', 'production', 'test'].includes(nodeEnv)) {
    warnings.push(`Non-standard NODE_ENV: "${nodeEnv}". Expected development, production, or test.`);
  }

  return {
    valid: errors.length === 0,
    warnings,
    errors,
  };
}

/**
 * Maps providers to explicit typed feature states:
 * - ENABLED: All credentials present AND permitted by policy
 * - DISABLED_MISSING_CREDENTIAL: Required keys absent
 * - DISABLED_BY_POLICY: Feature flag or policy disabled
 * - DEGRADED: Partial credentials or rate-limited
 */
export function getProviderFeatureFlagStates(): Record<string, { state: ProviderFeatureState; details: string }> {
  const flags = getFeatureFlags();
  const result: Record<string, { state: ProviderFeatureState; details: string }> = {};

  for (const provider of KNOWN_RESEARCH_PROVIDERS) {
    let configuredCount = 0;
    const missingKeys: string[] = [];

    for (const key of provider.requiredEnvKeys) {
      const val = process.env[key];
      if (val && val.trim().length > 0 && !val.startsWith('MY_')) {
        configuredCount++;
      } else {
        missingKeys.push(key);
      }
    }

    if (flags.maintenanceMode) {
      result[provider.name] = {
        state: 'DISABLED_BY_POLICY',
        details: 'System is currently in maintenance mode',
      };
    } else if (provider.category === 'INFERENCE' && !flags.enableAIGeneration) {
      result[provider.name] = {
        state: 'DISABLED_BY_POLICY',
        details: 'AI generation policy flag is disabled',
      };
    } else if (configuredCount === 0) {
      result[provider.name] = {
        state: 'DISABLED_MISSING_CREDENTIAL',
        details: `Missing required credentials [${missingKeys.join(', ')}]`,
      };
    } else if (missingKeys.length > 0) {
      result[provider.name] = {
        state: 'DEGRADED',
        details: `Partially configured (${configuredCount}/${provider.requiredEnvKeys.length}). Missing: [${missingKeys.join(', ')}]`,
      };
    } else {
      result[provider.name] = {
        state: 'ENABLED',
        details: 'Provider credentials configured and active under policy',
      };
    }
  }

  return result;
}

/**
 * Schema Validation: Validates that public config has required fields and zero secrets.
 */
export function validatePublicConfigSchema(config: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!config || typeof config !== 'object') {
    return { valid: false, errors: ['Configuration must be a non-null object'] };
  }

  const obj = config as Record<string, unknown>;
  const requiredStringProps = ['appName', 'version', 'architectureVersion', 'currentPhase', 'appUrl', 'apiPrefix'];
  for (const prop of requiredStringProps) {
    if (typeof obj[prop] !== 'string' || (obj[prop] as string).trim() === '') {
      errors.push(`Missing or invalid string property: "${prop}"`);
    }
  }

  // Structural assertion: zero secrets
  const forbiddenKeyRegex = /(api_?key|secret|token|password|auth|authorization|credential|cookie|private_?key)/i;
  for (const key of Object.keys(obj)) {
    if (forbiddenKeyRegex.test(key)) {
      errors.push(`Secret field detected in public configuration: "${key}"`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Schema Validation: Validates server configuration schema.
 */
export function validateServerConfigSchema(config: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!config || typeof config !== 'object') {
    return { valid: false, errors: ['Configuration must be a non-null object'] };
  }

  const obj = config as Record<string, unknown>;
  if (typeof obj.port !== 'number' || obj.port <= 0 || obj.port > 65535) {
    errors.push('port must be a valid number between 1 and 65535');
  }
  if (typeof obj.host !== 'string' || obj.host.trim() === '') {
    errors.push('host must be a non-empty string');
  }
  if (typeof obj.nodeEnv !== 'string' || !['development', 'production', 'test'].includes(obj.nodeEnv)) {
    errors.push('nodeEnv must be development, production, or test');
  }

  return { valid: errors.length === 0, errors };
}
