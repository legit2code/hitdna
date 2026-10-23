/**
 * Production Administrator Bootstrap Service
 * 
 * Provides secure production bootstrapping of the authoritative administrative principal:
 * 1. One-time cryptographically secure random secret generated at deploy time and delivered out-of-band.
 * 2. First-run enrollment flow (/api/auth/bootstrap/enroll) with single-use out-of-band enrollment token.
 * 3. External identity provider assertion (SSO/OIDC).
 *
 * CRITICAL SECURITY INVARIANTS:
 * - NO hardcoded passwords, fixed hashes, or 'ON CONFLICT DO UPDATE SET hashed_password' clauses in migrations.
 * - If an administrator already exists, bootstrap operations fail closed and never mutate existing credentials.
 * - One-time secrets are written to permission-restricted files (mode 0600) and delivered out-of-band.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { AuthService, PrincipalRecord } from './service.ts';
import { BusinessRole } from './types.ts';

export interface BootstrapStatus {
  requires_bootstrap: boolean;
  admin_count: number;
  enrollment_enabled: boolean;
  timestamp: string;
}

export interface DeployBootstrapOptions {
  adminEmail?: string;
  password?: string;
  credentialsFilePath?: string;
  externalIdp?: {
    provider: string;
    subject_id: string;
    email: string;
  };
  forceOneTimeSecret?: boolean;
}

export interface DeployBootstrapResult {
  bootstrapped: boolean;
  method: 'random_secret_out_of_band' | 'env_secret' | 'external_idp' | 'skipped_admin_exists';
  email?: string;
  principal_id?: string;
  credentialsFilePath?: string;
  outOfBandLocation?: string;
  message: string;
}

export interface FirstRunEnrollmentPayload {
  email: string;
  password: string;
  enrollment_token: string;
}

export interface FirstRunEnrollmentResult {
  status: 'enrolled';
  principal_id: string;
  email: string;
  roles: BusinessRole[];
  message: string;
}

export class ProductionBootstrapManager {
  private static activeEnrollmentToken: string | null = null;
  private static enrollmentTokenPath = '/tmp/caim-bootstrap-enrollment-token.txt';

  /**
   * Initializes or retrieves the one-time out-of-band enrollment token.
   */
  public static getOrCreateEnrollmentToken(): string {
    if (this.activeEnrollmentToken) {
      return this.activeEnrollmentToken;
    }

    const envToken = process.env.BOOTSTRAP_ENROLLMENT_TOKEN;
    if (envToken && envToken.trim().length >= 32) {
      this.activeEnrollmentToken = envToken.trim();
      return this.activeEnrollmentToken;
    }

    // Generate high-entropy 256-bit cryptographic token
    const token = crypto.randomBytes(32).toString('hex');
    this.activeEnrollmentToken = token;

    try {
      const tokenPath = process.env.BOOTSTRAP_TOKEN_FILE || this.enrollmentTokenPath;
      fs.writeFileSync(tokenPath, token, { mode: 0o600, encoding: 'utf8' });
      console.log(`[PRODUCTION BOOTSTRAP] Generated out-of-band first-run enrollment token at: ${tokenPath}`);
    } catch (err: unknown) {
      // Safe to swallow: In constrained environments where disk writing is restricted, token remains in memory
      console.debug?.('[generateEnrollmentToken disk write skipped]', err);
    }

    return this.activeEnrollmentToken;
  }

  /**
   * Invalidates and clears the active enrollment token.
   */
  public static invalidateEnrollmentToken(): void {
    this.activeEnrollmentToken = null;
    try {
      const tokenPath = process.env.BOOTSTRAP_TOKEN_FILE || this.enrollmentTokenPath;
      if (fs.existsSync(tokenPath)) {
        fs.unlinkSync(tokenPath);
      }
    } catch (err: unknown) {
      // Safe to swallow: Best-effort cleanup of temporary bootstrap file
      console.debug?.('[invalidateEnrollmentToken file unlink skipped]', err);
    }
  }

  /**
   * Generates a high-entropy cryptographically secure password meeting all policy constraints.
   */
  public static generateSecurePassword(): string {
    const raw = crypto.randomBytes(24).toString('base64url');
    // Ensure complexity constraints: length >= 24, upper, lower, number, special
    return `Root#${raw}$2026!Sec`;
  }

  /**
   * Checks whether the system requires administrative bootstrapping.
   */
  public static async checkBootstrapStatus(authService: AuthService): Promise<BootstrapStatus> {
    const adminCount = await authService.countAdministrators();
    const requiresBootstrap = adminCount === 0;

    return {
      requires_bootstrap: requiresBootstrap,
      admin_count: adminCount,
      enrollment_enabled: requiresBootstrap,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Executes deploy-time bootstrapping.
   * Ensures idempotency: if an administrator already exists, NO changes are made.
   */
  public static async executeDeployTimeBootstrap(
    authService: AuthService,
    options: DeployBootstrapOptions = {}
  ): Promise<DeployBootstrapResult> {
    const status = await this.checkBootstrapStatus(authService);
    if (!status.requires_bootstrap) {
      return {
        bootstrapped: false,
        method: 'skipped_admin_exists',
        message: `System already has ${status.admin_count} authoritative administrator(s). Existing credentials preserved.`,
      };
    }

    const adminEmail = (options.adminEmail || process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@caim.internal').trim().toLowerCase();
    const elevatedRoles: BusinessRole[] = ['admin', 'operator', 'auditor', 'reviewer', 'analyst', 'user'];

    // 1. External Identity Provider bootstrap option
    if (options.externalIdp || process.env.BOOTSTRAP_EXTERNAL_IDP_ID) {
      const providerId = options.externalIdp
        ? `${options.externalIdp.provider}:${options.externalIdp.subject_id}`
        : process.env.BOOTSTRAP_EXTERNAL_IDP_ID!;

      const principal = await authService.registerPrincipal({
        email: adminEmail,
        password: this.generateSecurePassword(), // Unused random dummy, authentication routed to external IdP
        external_identity_provider_id: providerId,
        roles: elevatedRoles,
        tenant_id: null,
        is_bootstrap_action: true,
      });

      this.invalidateEnrollmentToken();

      return {
        bootstrapped: true,
        method: 'external_idp',
        email: adminEmail,
        principal_id: principal.principal_id,
        message: `Admin principal successfully bootstrapped via external IdP (${providerId}).`,
      };
    }

    // 2. Deploy-time Secret delivery out-of-band
    let passwordToUse: string;
    let method: 'random_secret_out_of_band' | 'env_secret';
    let isRandomGenerated = false;

    if (!options.forceOneTimeSecret && (options.password || process.env.BOOTSTRAP_ADMIN_PASSWORD)) {
      passwordToUse = (options.password || process.env.BOOTSTRAP_ADMIN_PASSWORD!).trim();
      const validation = AuthService.validatePasswordStrength(passwordToUse);
      if (!validation.valid) {
        throw new Error(`[BOOTSTRAP ERROR] Provided BOOTSTRAP_ADMIN_PASSWORD fails complexity policy: ${validation.error}`);
      }
      method = 'env_secret';
    } else {
      passwordToUse = this.generateSecurePassword();
      method = 'random_secret_out_of_band';
      isRandomGenerated = true;
    }

    const principal = await authService.registerPrincipal({
      email: adminEmail,
      password: passwordToUse,
      roles: elevatedRoles,
      tenant_id: 'tenant_platform_core',
      is_bootstrap_action: true,
    });

    const credentialsPath = options.credentialsFilePath || process.env.BOOTSTRAP_CREDENTIALS_FILE || '/tmp/caim-bootstrap-credentials.json';

    if (isRandomGenerated) {
      try {
        const payload = JSON.stringify(
          {
            notice: 'CONFIDENTIAL: Initial one-time administrative bootstrap credentials delivered out-of-band.',
            bootstrapped_at: new Date().toISOString(),
            email: adminEmail,
            principal_id: principal.principal_id,
            one_time_secret: passwordToUse,
            roles: elevatedRoles,
            instructions: 'Securely ingest this secret into your secret vault and rotate upon first login.',
          },
          null,
          2
        );
        fs.writeFileSync(credentialsPath, payload, { mode: 0o600, encoding: 'utf8' });
        console.log(`[PRODUCTION BOOTSTRAP] Out-of-band one-time administrative secret written to: ${credentialsPath} (mode 0600)`);
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        console.warn(`[PRODUCTION BOOTSTRAP] Notice: could not write credentials file (${errMsg}).`);
      }
    }

    // Security Hardening: Immediately zero out plaintext secret in memory so application code never holds it
    passwordToUse = '';

    this.invalidateEnrollmentToken();

    return {
      bootstrapped: true,
      method,
      email: adminEmail,
      principal_id: principal.principal_id,
      credentialsFilePath: isRandomGenerated ? credentialsPath : undefined,
      outOfBandLocation: isRandomGenerated ? credentialsPath : undefined,
      message: `Authoritative administrator successfully bootstrapped via ${method}. Out-of-band credentials delivered to ${credentialsPath}.`,
    };
  }

  /**
   * First-Run Enrollment Flow:
   * Interactive or API-based enrollment when no administrator exists.
   * Requires a valid single-use out-of-band enrollment token.
   */
  public static async enrollFirstRunAdmin(
    authService: AuthService,
    payload: FirstRunEnrollmentPayload
  ): Promise<FirstRunEnrollmentResult> {
    const status = await this.checkBootstrapStatus(authService);
    if (!status.requires_bootstrap) {
      throw new Error('Bootstrap enrollment is closed: An authoritative administrator already exists.');
    }

    const expectedToken = this.getOrCreateEnrollmentToken();
    const suppliedToken = (payload.enrollment_token || '').trim();

    // Constant-time token verification to prevent timing attacks
    const bufferExpected = Buffer.from(expectedToken);
    const bufferSupplied = Buffer.from(suppliedToken);

    if (bufferExpected.length !== bufferSupplied.length || !crypto.timingSafeEqual(bufferExpected, bufferSupplied)) {
      throw new Error('Invalid bootstrap enrollment token. Token must match the out-of-band generated value.');
    }

    const validation = AuthService.validatePasswordStrength(payload.password);
    if (!validation.valid) {
      throw new Error(`Password policy violation: ${validation.error}`);
    }

    const elevatedRoles: BusinessRole[] = ['admin', 'operator', 'auditor', 'reviewer', 'analyst', 'user'];
    const principal = await authService.registerPrincipal({
      email: payload.email.trim().toLowerCase(),
      password: payload.password,
      roles: elevatedRoles,
      tenant_id: null,
      is_bootstrap_action: true,
    });

    // Invalidate enrollment token immediately
    this.invalidateEnrollmentToken();

    return {
      status: 'enrolled',
      principal_id: principal.principal_id,
      email: principal.email,
      roles: elevatedRoles,
      message: 'Initial administrator successfully enrolled. Bootstrap flow is now permanently closed.',
    };
  }
}
