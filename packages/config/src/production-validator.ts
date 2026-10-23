import { ServerConfig } from './schema.ts';
import { getServerConfig } from './loaders.ts';

export interface ConfigValidationFinding {
  key: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  category: 'MANDATORY_SECRET' | 'INSECURE_DEFAULT' | 'OPTIONAL_ADAPTER' | 'ENVIRONMENT_MISMATCH' | 'DEV_FIXTURE';
  message: string;
  recommendation: string;
  passed: boolean;
}

export interface ProductionConfigValidationReport {
  timestamp: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  isValid: boolean;
  canDeployToProduction: boolean;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  findings: ConfigValidationFinding[];
  adapterStatuses: Record<string, {
    status: 'READY' | 'DISABLED_OPTIONAL' | 'DISABLED_MISSING_CREDENTIAL';
    credentialConfigured: boolean;
    operationalImpact: string;
  }>;
}

export class ProductionConfigValidator {
  /**
   * Validates the configuration against strict production security standards.
   * In 'production' environment, fails fast if any CRITICAL or HIGH finding is detected.
   */
  static validate(customConfig?: Partial<ServerConfig>, targetEnv?: 'development' | 'staging' | 'production' | 'test'): ProductionConfigValidationReport {
    const config = customConfig ? { ...getServerConfig(), ...customConfig } : getServerConfig();
    const env = targetEnv || (process.env.APP_ENV as any) || (config.appEnv as any) || (process.env.NODE_ENV as any) || config.env || 'development';
    const isProduction = env !== 'development' && env !== 'test';

    const findings: ConfigValidationFinding[] = [];

    // 1. Mandatory Secrets & Keys Check
    // Database connection check
    const hasDatabaseUrl = Boolean(
      (process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0) ||
      (process.env.SUPABASE_DB_URL && process.env.SUPABASE_DB_URL.trim().length > 0) ||
      (process.env.POSTGRES_URL && process.env.POSTGRES_URL.trim().length > 0) ||
      (config.providers.supabaseUrl && config.providers.supabaseServiceKey) ||
      ((customConfig as any)?.databaseUrl && (customConfig as any).databaseUrl.trim().length > 0)
    );
    // Master Key / Secret Key validation
    const hasSupabaseServiceKey = Boolean(config.providers.supabaseServiceKey && config.providers.supabaseServiceKey.trim().length > 0);
    const hasSigningPrivateKey = Boolean(
      (config.signing.privateKey && config.signing.privateKey.trim().length > 0) ||
      (process.env.SIGNING_PRIVATE_KEY && process.env.SIGNING_PRIVATE_KEY.trim().length > 0) ||
      (process.env.KMS_KEY_ID && process.env.KMS_KEY_ID.trim().length > 0) ||
      (process.env.CLOUD_KMS_KEY_NAME && process.env.CLOUD_KMS_KEY_NAME.trim().length > 0)
    );
    const hasGeminiApiKey = Boolean(config.geminiApiKey && config.geminiApiKey.trim().length > 0);

    if (isProduction) {
      findings.push({
        key: 'DATABASE_URL',
        severity: 'CRITICAL',
        category: 'MANDATORY_SECRET',
        message: hasDatabaseUrl
          ? 'Production PostgreSQL connection string (DATABASE_URL) configured'
          : 'Missing mandatory DATABASE_URL in production mode. Ephemeral database fallback is strictly prohibited.',
        recommendation: 'Configure DATABASE_URL with a durable PostgreSQL connection string (e.g. Supabase or Cloud SQL).',
        passed: hasDatabaseUrl,
      });

      findings.push({
        key: 'SIGNING_PRIVATE_KEY',
        severity: 'CRITICAL',
        category: 'MANDATORY_SECRET',
        message: hasSigningPrivateKey ? 'Production Ed25519/KMS private signing key configured' : 'Missing mandatory SIGNING_PRIVATE_KEY for package attestation',
        recommendation: 'Configure a secure Ed25519 private key or Cloud KMS key reference in production.',
        passed: hasSigningPrivateKey,
      });

      findings.push({
        key: 'GEMINI_API_KEY',
        severity: 'CRITICAL',
        category: 'MANDATORY_SECRET',
        message: hasGeminiApiKey ? 'Server-side GEMINI_API_KEY is configured' : 'Missing GEMINI_API_KEY for server-side AI evaluation and analysis',
        recommendation: 'Set GEMINI_API_KEY as a secure server-side environment secret.',
        passed: hasGeminiApiKey,
      });
    } else {
      findings.push({
        key: 'DATABASE_URL',
        severity: hasDatabaseUrl ? 'INFORMATIONAL' : 'LOW',
        category: 'OPTIONAL_ADAPTER',
        message: hasDatabaseUrl
          ? 'PostgreSQL database connection string (DATABASE_URL) configured'
          : 'DATABASE_URL optional in development (ephemeral pg-mem database used for local dev/testing)',
        recommendation: 'Configure DATABASE_URL to test against a live PostgreSQL instance.',
        passed: true,
      });

      findings.push({
        key: 'SIGNING_PRIVATE_KEY',
        severity: 'INFORMATIONAL',
        category: 'MANDATORY_SECRET',
        message: hasSigningPrivateKey ? 'Signing private key configured' : 'Signing private key optional in development (ephemeral key generated on demand)',
        recommendation: 'In dev/test, an ephemeral in-memory Ed25519 keypair is used automatically.',
        passed: true,
      });

      findings.push({
        key: 'GEMINI_API_KEY',
        severity: hasGeminiApiKey ? 'INFORMATIONAL' : 'MEDIUM',
        category: 'MANDATORY_SECRET',
        message: hasGeminiApiKey ? 'GEMINI_API_KEY is configured' : 'GEMINI_API_KEY not configured (mock/fallback evaluation mode active)',
        recommendation: 'Provide GEMINI_API_KEY to test live generative AI features.',
        passed: true,
      });
    }

    // Insecure Default Checks
    const isDefaultDevKeyId = config.signing.keyId === 'caim-v2-dev-key';
    if (isProduction && isDefaultDevKeyId) {
      findings.push({
        key: 'SIGNING_KEY_ID',
        severity: 'HIGH',
        category: 'INSECURE_DEFAULT',
        message: 'Insecure default SIGNING_KEY_ID ("caim-v2-dev-key") detected in production',
        recommendation: 'Set a dedicated production key ID (e.g. "caim-prod-kms-2026-v1").',
        passed: false,
      });
    } else {
      findings.push({
        key: 'SIGNING_KEY_ID',
        severity: 'INFORMATIONAL',
        category: 'INSECURE_DEFAULT',
        message: `Signing Key ID is "${config.signing.keyId}"`,
        recommendation: 'Valid for current environment.',
        passed: true,
      });
    }

    // JWT Secret Validation
    const jwtSecret = config.auth?.jwtSecret || (customConfig as any)?.jwtSecret || (customConfig as any)?.auth?.jwtSecret || process.env.JWT_SECRET || '';
    const insecureJwtSecrets = [
      'caim-ephemeral-jwt-signing-secret-default-2026',
      'caim-default-secret',
      'secret',
      'changeme',
      'admin',
      'dev-secret',
      '123456',
      'caim-dev-jwt-secret',
      'caim-enterprise-v2-jwt-secret-authenticated-production-token-2026',
      'caim-internal-mesh-secret-key-2026',
      'caim-discovery-service-secret-2026',
      'supabase-managed-jwt-secret-verification-token',
      'inv_enterprise_tok123',
      'inv_partner_tok456',
      'inv_tenant_acme_corp',
    ];
    const isWeakOrMissingJwt = !jwtSecret || jwtSecret.length < 32 || insecureJwtSecrets.includes(jwtSecret.toLowerCase());
    if (isProduction) {
      findings.push({
        key: 'JWT_SECRET',
        severity: 'CRITICAL',
        category: 'INSECURE_DEFAULT',
        message: !jwtSecret 
          ? 'Missing mandatory JWT_SECRET in production mode'
          : (isWeakOrMissingJwt ? `Insecure or trivial JWT_SECRET ("${jwtSecret.substring(0, 4)}***") detected in production` : 'Production JWT_SECRET configured'),
        recommendation: 'Configure a cryptographically random, high-entropy JWT secret (minimum 32 characters).',
        passed: !isWeakOrMissingJwt,
      });
    }

    // Invitation Signing Secret Validation
    const invitationSecret = (config.auth as any)?.invitationSigningSecret || (customConfig as any)?.invitationSigningSecret || (customConfig as any)?.auth?.invitationSigningSecret || process.env.INVITATION_SIGNING_SECRET || '';
    const isWeakOrMissingInv = !invitationSecret || invitationSecret.length < 32 || insecureJwtSecrets.includes(invitationSecret.toLowerCase()) || (jwtSecret && invitationSecret === jwtSecret);
    if (isProduction) {
      findings.push({
        key: 'INVITATION_SIGNING_SECRET',
        severity: 'CRITICAL',
        category: 'INSECURE_DEFAULT',
        message: !invitationSecret
          ? 'Missing mandatory INVITATION_SIGNING_SECRET in production mode'
          : (invitationSecret === jwtSecret
            ? 'INVITATION_SIGNING_SECRET must not reuse JWT_SECRET'
            : (isWeakOrMissingInv ? `Insecure or trivial INVITATION_SIGNING_SECRET ("${invitationSecret.substring(0, 4)}***") detected in production` : 'Production INVITATION_SIGNING_SECRET configured')),
        recommendation: 'Configure a cryptographically random, high-entropy invitation signing secret (minimum 32 characters, distinct from JWT_SECRET).',
        passed: !isWeakOrMissingInv,
      });
    }

    // Service-to-Service Secret Validation
    const serviceSecret = process.env.SERVICE_TO_SERVICE_SECRET || '';
    const insecureServiceSecrets = [
      'caim-internal-mesh-secret-key-2026',
      'caim-discovery-service-secret-2026',
      'caim-default-secret',
      'secret',
      'changeme',
      'admin',
      'dev-secret',
    ];
    const isWeakOrInsecureServiceSecret = serviceSecret && insecureServiceSecrets.includes(serviceSecret.toLowerCase());
    if (isProduction && isWeakOrInsecureServiceSecret) {
      findings.push({
        key: 'SERVICE_TO_SERVICE_SECRET',
        severity: 'CRITICAL',
        category: 'INSECURE_DEFAULT',
        message: 'Insecure hardcoded or default SERVICE_TO_SERVICE_SECRET detected in production',
        recommendation: 'Configure a cryptographically random, high-entropy service secret via external secret manager.',
        passed: false,
      });
    }

    // Bootstrap Admin Password Validation
    const bootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || '';
    const insecurePasswords = ['admin', 'password', 'admin123', 'changeme', 'caimadmin', 'secret'];
    const isDefaultBootstrapPassword = bootstrapPassword && insecurePasswords.includes(bootstrapPassword.toLowerCase());
    if (isProduction && isDefaultBootstrapPassword) {
      findings.push({
        key: 'BOOTSTRAP_ADMIN_PASSWORD',
        severity: 'CRITICAL',
        category: 'INSECURE_DEFAULT',
        message: `Insecure default BOOTSTRAP_ADMIN_PASSWORD ("${bootstrapPassword}") detected in production`,
        recommendation: 'Generate a high-entropy initial bootstrap secret out-of-band or use IDP federation.',
        passed: false,
      });
    }

    // Simulation Disallowed in Production
    const allowSimulation = process.env.CAIM_ALLOW_SIMULATION === 'true';
    if (isProduction && allowSimulation) {
      findings.push({
        key: 'CAIM_ALLOW_SIMULATION',
        severity: 'CRITICAL',
        category: 'ENVIRONMENT_MISMATCH',
        message: 'CAIM_ALLOW_SIMULATION=true is strictly prohibited in production mode. Production runtime must never simulate sandbox or analysis behavior.',
        recommendation: 'Remove CAIM_ALLOW_SIMULATION or set it to false in production environments.',
        passed: false,
      });
    }

    // Localhost Production Database Check
    const dbUrl = process.env.DATABASE_URL || '';
    const isLocalhostDb = dbUrl.includes('localhost') || dbUrl.includes('127.0.0.1') || dbUrl.includes('::1');
    const allowLocalProdDb = process.env.CAIM_ALLOW_LOCAL_PROD_DB === 'true';
    if (isProduction && hasDatabaseUrl && isLocalhostDb && !allowLocalProdDb) {
      findings.push({
        key: 'DATABASE_URL_HOST',
        severity: 'CRITICAL',
        category: 'ENVIRONMENT_MISMATCH',
        message: 'DATABASE_URL points to localhost/127.0.0.1 in production mode without explicit CAIM_ALLOW_LOCAL_PROD_DB opt-in.',
        recommendation: 'Configure DATABASE_URL with a managed, durable cloud PostgreSQL host.',
        passed: false,
      });
    }

    // App URL Insecure Host Check in Production
    const isLocalhostAppUrl = config.appUrl.includes('localhost') || config.appUrl.includes('127.0.0.1');
    if (isProduction && isLocalhostAppUrl) {
      findings.push({
        key: 'APP_URL',
        severity: 'HIGH',
        category: 'ENVIRONMENT_MISMATCH',
        message: `APP_URL points to localhost (${config.appUrl}) in production mode`,
        recommendation: 'Set APP_URL to the fully-qualified HTTPS production domain.',
        passed: false,
      });
    } else {
      findings.push({
        key: 'APP_URL',
        severity: 'INFORMATIONAL',
        category: 'ENVIRONMENT_MISMATCH',
        message: `APP_URL is ${config.appUrl}`,
        recommendation: 'Valid application base URL.',
        passed: true,
      });
    }

    // 3. Optional Adapters Status Analysis
    const adapterStatuses: Record<string, {
      status: 'READY' | 'DISABLED_OPTIONAL' | 'DISABLED_MISSING_CREDENTIAL';
      credentialConfigured: boolean;
      operationalImpact: string;
    }> = {
      github: {
        status: config.providers.githubToken ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.githubToken),
        operationalImpact: config.providers.githubToken 
          ? 'Full GitHub API discovery, release scanning, and authenticated rate limits (5,000 req/hr).'
          : 'Public repository discovery only (60 req/hr unauthenticated rate limit).',
      },
      huggingface: {
        status: config.providers.huggingfaceApiKey ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.huggingfaceApiKey),
        operationalImpact: config.providers.huggingfaceApiKey
          ? 'Authenticated model card and dataset extraction from Hugging Face Hub.'
          : 'Public model discovery only; gated models skipped.',
      },
      e2b: {
        status: config.providers.e2bApiKey ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.e2bApiKey),
        operationalImpact: config.providers.e2bApiKey
          ? 'Cloud-hosted Firecracker microVM dynamic sandboxing enabled.'
          : 'Local isolated Node.js container / VM process sandbox enabled as baseline.',
      },
      sentry: {
        status: config.providers.sentryDsn ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.sentryDsn),
        operationalImpact: config.providers.sentryDsn
          ? 'Remote crash and exception telemetry forwarded to Sentry.'
          : 'Local structured audit logs and OpenTelemetry in-memory collector active.',
      },
      supabase: {
        status: hasSupabaseServiceKey ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: hasSupabaseServiceKey,
        operationalImpact: hasSupabaseServiceKey
          ? 'Managed PostgreSQL with RLS, Vault, and Realtime replication.'
          : 'Local PostgreSQL / in-memory transaction store active.',
      },
    };

    // 4. Development Fixtures Check
    const allowDevFixtures = !isProduction;
    findings.push({
      key: 'DEV_FIXTURES_POLICY',
      severity: 'INFORMATIONAL',
      category: 'DEV_FIXTURE',
      message: allowDevFixtures 
        ? 'Development fixtures and synthetic corpus replay permitted in non-production environment'
        : 'Development fixtures isolated; strictly live data stores in production',
      recommendation: 'Ensure mock credentials and test seeds are excluded from release containers.',
      passed: true,
    });

    const totalChecks = findings.length;
    const failedChecks = findings.filter(f => !f.passed).length;
    const passedChecks = totalChecks - failedChecks;

    // In production, any CRITICAL or HIGH failure prevents deployment
    const hasCriticalOrHighFailure = findings.some(f => !f.passed && (f.severity === 'CRITICAL' || f.severity === 'HIGH'));
    const canDeployToProduction = !hasCriticalOrHighFailure;
    const isValid = failedChecks === 0;

    return {
      timestamp: new Date().toISOString(),
      environment: env,
      isValid,
      canDeployToProduction,
      totalChecks,
      passedChecks,
      failedChecks,
      findings,
      adapterStatuses,
    };
  }

  /**
   * Throws ConfigurationError if production requirements are violated when running in production or staging.
   */
  static assertProductionReadiness(customConfig?: Partial<ServerConfig>, targetEnv?: 'development' | 'staging' | 'production' | 'test'): void {
    const config = customConfig ? { ...getServerConfig(), ...customConfig } : getServerConfig();
    const env = targetEnv || (process.env.APP_ENV as any) || (config.appEnv as any) || (process.env.NODE_ENV as any) || (config.env as any) || 'development';
    const report = this.validate(config, env);
    if (!report.canDeployToProduction) {
      const issues = report.findings.filter(f => !f.passed).map(f => `[${f.severity}] ${f.key}: ${f.message}`).join('; ');
      throw new Error(`[ProductionConfigViolation] Cannot deploy to ${env}. Failed security gates: ${issues}`);
    }
  }
}
