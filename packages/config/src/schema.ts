import { z } from 'zod';

export const FeatureFlagsSchema = z.object({
  enableDynamicSandbox: z.boolean().default(true),
  enableEvasionDetection: z.boolean().default(true),
  enableTaintAnalysis: z.boolean().default(true),
  enableHybridRAG: z.boolean().default(true),
  enableContinuousMonitoring: z.boolean().default(false),
  enableAutomatedRemediation: z.boolean().default(false),
  enableModelCardAIBOM: z.boolean().default(true),
});

export type FeatureFlags = z.infer<typeof FeatureFlagsSchema>;

export const ModelConfigSchema = z.object({
  geminiModelDefault: z.string().default('gemini-2.5-flash'),
  geminiModelPro: z.string().default('gemini-2.5-pro'),
  geminiEmbeddingModel: z.string().default('text-embedding-004'),
  temperature: z.number().min(0).max(2).default(0.2),
  maxOutputTokens: z.number().positive().default(8192),
});

export type ModelConfig = z.infer<typeof ModelConfigSchema>;

export const PublicConfigSchema = z.object({
  env: z.enum(['development', 'staging', 'production', 'test']).default('development'),
  appEnv: z.enum(['development', 'staging', 'production', 'test']).default('development'),
  appUrl: z.string().url().default('http://localhost:3000'),
  platformVersion: z.string().default('2.0.1'),
  baseline: z.string().default('V2.0.1 Controlled Implementation Baseline'),
  apiPrefix: z.string().default('/api'),
  features: FeatureFlagsSchema,
  models: z.object({
    defaultModel: z.string().default('gemini-2.5-flash'),
    embeddingModel: z.string().default('text-embedding-004'),
  }),
});

export type PublicConfig = z.infer<typeof PublicConfigSchema>;

export const SigningConfigSchema = z.object({
  keyId: z.string().default('caim-v2-dev-key'),
  algorithm: z.enum(['Ed25519', 'RS256', 'ES256']).default('Ed25519'),
  privateKey: z.string().optional(),
  publicKey: z.string().optional(),
});

export type SigningConfig = z.infer<typeof SigningConfigSchema>;

export const OptionalProvidersSchema = z.object({
  githubToken: z.string().optional(),
  huggingfaceApiKey: z.string().optional(),
  e2bApiKey: z.string().optional(),
  sentryDsn: z.string().optional(),
  supabaseServiceKey: z.string().optional(),
  supabaseUrl: z.string().url().optional(),
});

export type OptionalProviders = z.infer<typeof OptionalProvidersSchema>;

export const AuthConfigSchema = z.object({
  jwtSecret: z.string().optional(),
  invitationSigningSecret: z.string().optional(),
  serviceSecret: z.string().optional(),
  discoveryServiceToken: z.string().optional(),
  serviceTenantScopes: z.record(z.string(), z.array(z.string())).optional(),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;

export const ServerConfigSchema = z.object({
  env: z.enum(['development', 'staging', 'production', 'test']).default('development'),
  appEnv: z.enum(['development', 'staging', 'production', 'test']).default('development'),
  port: z.coerce.number().default(3000),
  host: z.string().default('0.0.0.0'),
  appUrl: z.string().url().default('http://localhost:3000'),
  corsOrigins: z.array(z.string()).default(['http://localhost:3000', 'http://127.0.0.1:3000']),
  trustProxy: z.union([z.boolean(), z.string(), z.number()]).default(1),
  bodyLimit: z.string().default('256kb'),
  ingestionBodyLimit: z.string().default('10mb'),
  shutdownTimeoutMs: z.coerce.number().default(10000),
  geminiApiKey: z.string().min(1, 'GEMINI_API_KEY is required for server-side operations').optional(),
  auth: AuthConfigSchema.default({}),
  signing: SigningConfigSchema,
  providers: OptionalProvidersSchema,
  features: FeatureFlagsSchema,
  models: ModelConfigSchema,
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

export const WorkerConfigSchema = z.object({
  workerDomain: z.string(),
  concurrency: z.number().int().positive().default(4),
  heartbeatIntervalMs: z.number().int().positive().default(10000),
  taskTimeoutMs: z.number().int().positive().default(300000),
  sandboxMemoryLimitMb: z.number().int().positive().default(1024),
  isolatedProcess: z.boolean().default(true),
  geminiApiKey: z.string().optional(),
  providers: OptionalProvidersSchema,
});

export type WorkerConfig = z.infer<typeof WorkerConfigSchema>;
