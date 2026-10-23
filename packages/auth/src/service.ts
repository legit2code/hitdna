/**
 * Real Authentication & Session Service
 * Manages principal registrations, bcrypt password verification, JWT issuance, and refresh token rotation.
 */

import {
  hashPassword,
  hashPasswordSync,
  verifyPassword,
  verifyPasswordWithRehashCheck,
  getBreachedPasswordChecker,
  passwordBackoffTracker,
} from './password.ts';
import {
  signAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  safeCompareSecrets,
  incrementPrincipalTokenVersion,
  revokeTokenByJti,
  getJwtSecret,
} from './jwt.ts';
import { BusinessRole, PrincipalContext, ServiceIdentity, SecurityClassificationRank, UnauthorizedAccessError } from './types.ts';
import { resolvePrincipalClaims, resolveClassificationClearance } from './claims.ts';
import { isAuthorizedForVault } from './vault.ts';
import { EmailSender, StubEmailSender, getDefaultEmailSender } from './email-sender.ts';
import { tenantInvitationManager } from './invitation.ts';
import type { DatabaseClient } from '@caim/db';

export interface PrincipalRecord {
  principal_id: string;
  email: string;
  hashed_password: string;
  external_identity_provider_id?: string | null;
  roles: BusinessRole[];
  tenant_id?: string | null;
  created_at: string;
  last_login_at?: string | null;
  email_verified?: boolean;
  email_verification_token?: string | null;
  email_verification_expires_at?: string | null;
  token_version?: number;
}

function parseDbPrincipalRow(row: Record<string, unknown>): PrincipalRecord {
  return {
    principal_id: String(row.principal_id),
    email: String(row.email),
    hashed_password: String(row.hashed_password),
    external_identity_provider_id: row.external_identity_provider_id ? String(row.external_identity_provider_id) : null,
    roles: Array.isArray(row.roles) ? (row.roles as BusinessRole[]) : ['user'],
    tenant_id: row.tenant_id ? String(row.tenant_id) : null,
    created_at: String(row.created_at),
    last_login_at: row.last_login_at ? String(row.last_login_at) : null,
    email_verified: row.email_verified !== undefined ? Boolean(row.email_verified) : true,
    email_verification_token: row.email_verification_token ? String(row.email_verification_token) : null,
    email_verification_expires_at: row.email_verification_expires_at ? String(row.email_verification_expires_at) : null,
    token_version: row.token_version !== undefined ? parseInt(String(row.token_version), 10) : 1,
  };
}

export interface RefreshTokenRecord {
  token_id: string;
  principal_id: string;
  token_hash: string;
  family_id: string;
  expires_at: string;
  revoked_at?: string | null;
  used_at?: string | null;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number; // in seconds (e.g. 900 for 15m)
  principal: {
    principal_id: string;
    email: string;
    roles: BusinessRole[];
    tenant_id?: string | null;
    email_verified?: boolean;
  };
}

export class AuthService {
  private dbClient?: DatabaseClient;
  private emailSender: EmailSender;
  // Fallback high-performance in-memory cache / ledger for environments where DB table is mocked or initialized
  private static inMemoryPrincipals: Map<string, PrincipalRecord> = new Map();
  private static inMemoryRefreshTokens: Map<string, RefreshTokenRecord> = new Map();
  private static sharedStubEmailSender = getDefaultEmailSender();

  constructor(dbClient?: DatabaseClient, emailSender?: EmailSender) {
    this.dbClient = dbClient;
    this.emailSender = emailSender || AuthService.sharedStubEmailSender;
    // Default principals are NOT seeded on constructor initialization.
    // Must be explicitly invoked via seedDevelopmentPrincipals() in dev environments.
  }

  public getEmailSender(): EmailSender {
    return this.emailSender;
  }

  public setEmailSender(sender: EmailSender): void {
    this.emailSender = sender;
  }

  public static getSharedEmailSender(): StubEmailSender {
    return AuthService.sharedStubEmailSender;
  }

  /**
   * Explicit dev-only seed function.
   * Structurally unreachable in production: fails immediately if NODE_ENV === 'production'.
   * Never called from normal application startup or constructor.
   */
  public seedDevelopmentPrincipals(): void {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '[FATAL SECURITY VIOLATION] seedDevelopmentPrincipals() is strictly prohibited in production mode (NODE_ENV=production). ' +
        'Default accounts and development credentials must never be seeded into production.'
      );
    }
    AuthService.seedDevelopmentPrincipalsStatic();
  }

  public static seedDevelopmentPrincipals(): void {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '[FATAL SECURITY VIOLATION] seedDevelopmentPrincipals() is strictly prohibited in production mode (NODE_ENV=production). ' +
        'Default accounts and development credentials must never be seeded into production.'
      );
    }
    AuthService.seedDevelopmentPrincipalsStatic();
  }

  public static clearInMemoryPrincipals(): void {
    AuthService.inMemoryPrincipals.clear();
    AuthService.inMemoryRefreshTokens.clear();
  }

  public static getInMemoryPrincipals(): Map<string, PrincipalRecord> {
    return AuthService.inMemoryPrincipals;
  }

  /**
   * Counts active administrators across PostgreSQL and in-memory stores.
   */
  public async countAdministrators(): Promise<number> {
    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          `SELECT COUNT(*)::int as count FROM security.principals WHERE 'admin' = ANY(roles);`
        );
        if (res && res.rows && res.rows.length > 0) {
          const dbCount = Number(res.rows[0].count);
          if (!isNaN(dbCount)) return dbCount;
        }
      } catch {
        // Fallback to in-memory check
      }
    }
    let count = 0;
    for (const p of AuthService.inMemoryPrincipals.values()) {
      if (p.roles && p.roles.includes('admin')) {
        count++;
      }
    }
    return count;
  }

  /**
   * @deprecated Use seedDevelopmentPrincipals() explicitly. Retained with identical fail-closed check for backward compatibility.
   */
  public ensureDefaultPrincipals(): void {
    this.seedDevelopmentPrincipals();
  }

  private static seedDevelopmentPrincipalsStatic(): void {
    const defaultAccounts: Array<{ email: string; pass: string; roles: BusinessRole[]; tenant_id?: string }> = [
      { email: 'admin@caim.internal', pass: 'Admin#2026$RotatedRootKey!8472', roles: ['admin', 'operator', 'auditor', 'reviewer', 'analyst', 'user'] },
      { email: 'auditor@caim.internal', pass: 'Admin123!Secure', roles: ['auditor', 'analyst', 'user'] },
      { email: 'analyst@caim.internal', pass: 'Analyst123!Secure', roles: ['analyst', 'user'] },
      { email: 'reviewer@caim.internal', pass: 'Reviewer123!Secure', roles: ['reviewer', 'release_approver', 'user'] },
      { email: 'operator@caim.internal', pass: 'Operator123!Secure', roles: ['operator', 'auditor', 'user'] },
      { email: 'user@caim.internal', pass: 'User123!Secure', roles: ['user'] },
      { email: 'engineer@caim.internal', pass: 'Engineer123!Secure', roles: ['operator', 'admin', 'auditor', 'user'] },
    ];

    for (const acc of defaultAccounts) {
      const principal_id = `00000000-0000-0000-0001-${acc.email.split('@')[0].padEnd(12, '0').slice(0, 12)}`;
      const record: PrincipalRecord = {
        principal_id,
        email: acc.email,
        hashed_password: hashPasswordSync(acc.pass),
        roles: acc.roles,
        tenant_id: acc.tenant_id || null,
        created_at: new Date().toISOString(),
        email_verified: true,
      };
      AuthService.inMemoryPrincipals.set(acc.email, record);
    }
  }

  public static readonly invitationTokenTenantMap = new Map<string, string>();

  public static readonly domainTenantMap = new Map<string, string>([
    ['caim.internal', 'tenant-001'],
    ['enterprise.corp', 'tenant_enterprise'],
    ['partner.org', 'tenant_partner'],
  ]);

  /**
   * Determines tenant_id strictly server-side for self-registration.
   * Priority:
   * 1. Valid invitation token (e.g., inv_tenant123_...)
   * 2. Known domain-based tenant mapping or corporate domain sanitization
   * 3. Fallback default tenant ('tenant-default')
   * NEVER accepts caller-supplied tenant_id from request body for self-registration.
   */
  public determineTenantServerSide(options: { email: string; invitationToken?: string | null }): string | null {
    const { email, invitationToken } = options;

    // 1. Check invitation token
    if (invitationToken && typeof invitationToken === 'string' && invitationToken.trim().length > 0) {
      const validated = tenantInvitationManager.validateInvitation(invitationToken.trim(), {
        expectedEmail: email,
      });
      return validated.tenant_id;
    }

    // 2. Domain-based tenant assignment
    const domainMatch = email.match(/@([^@]+)$/);
    if (domainMatch && domainMatch[1]) {
      const domain = domainMatch[1].toLowerCase().trim();
      const domainTenant = AuthService.domainTenantMap.get(domain);
      if (domainTenant) return domainTenant;
      // Corporate domain sanitization (exclude public consumer mailboxes)
      if (domain !== 'gmail.com' && domain !== 'yahoo.com' && domain !== 'outlook.com' && domain !== 'hotmail.com' && domain !== 'icloud.com') {
        const sanitizedDomain = domain.replace(/[^a-z0-9]/g, '_');
        return `tenant_${sanitizedDomain}`;
      }
    }

    // 3. Isolated non-data-bearing pending state (NULL tenant) — no shared tenant-default assignment
    return null;
  }

  /**
   * Registers a new principal with bcrypt hashed password.
   *
   * SECURITY POLICY ENFORCEMENT:
   * 1. If called by an unauthenticated caller or without elevated admin authorization:
   *    - Any caller-supplied `roles` and `tenant_id` are completely ignored.
   *    - The assigned role is ALWAYS strictly `['user']`.
   *    - The assigned `tenant_id` is determined strictly server-side (from invitation token,
   *      domain mapping, or fallback default tenant) — NEVER from the request body.
   * 2. If called by an authenticated administrator holding capability grant (`allowElevatedRoles: true`):
   *    - Allows specifying elevated roles (e.g. `['admin']`) and explicit `tenant_id`.
   */
  public async registerPrincipal(data: {
    email: string;
    password: string;
    roles?: BusinessRole[] | string[];
    tenant_id?: string | null;
    invitation_token?: string | null;
    caller?: PrincipalContext | null;
    allowElevatedRoles?: boolean;
    is_admin_action?: boolean;
    is_bootstrap_action?: boolean;
    external_identity_provider_id?: string | null;
  }): Promise<Omit<PrincipalRecord, 'hashed_password'>> {
    const normalizedEmail = data.email.trim().toLowerCase();
    
    // Check collision in memory or DB
    if (AuthService.inMemoryPrincipals.has(normalizedEmail)) {
      throw new Error(`Principal with email '${normalizedEmail}' already exists.`);
    }

    // Enforce password strength policy
    if (data.password) {
      const strength = AuthService.validatePasswordStrength(data.password);
      if (!strength.valid) {
        throw new Error(`Password policy violation: ${strength.error}`);
      }
    }

    const hashed_password = await hashPassword(data.password);
    const principal_id = crypto.randomUUID();

    const isElevatedAdminCaller = Boolean(
      data.is_admin_action ||
      data.is_bootstrap_action ||
      (data.caller?.is_authenticated &&
        !data.caller.roles?.includes('anonymous') &&
        (data.caller.roles?.includes('admin') ||
         data.caller.capabilities?.includes('admin:manage_principals') ||
         data.caller.grants?.includes('admin:manage_principals')))
    );

    let roles: BusinessRole[];
    let tenant_id: string | null;

    if (isElevatedAdminCaller) {
      roles = data.roles && data.roles.length > 0 ? (data.roles as BusinessRole[]) : (['user'] as BusinessRole[]);
      tenant_id = data.tenant_id !== undefined ? data.tenant_id : this.determineTenantServerSide({ email: normalizedEmail });
    } else {
      // Unauthenticated caller or public self-registration:
      // CRITICAL SECURITY ENFORCEMENT (Prompt 5 Sections 12 & 13):
      // Client cannot choose privileged role or unauthorized tenant scope.
      // Required Invariant: CLIENT REQUESTS ROLE != ROLE IS AUTHORIZED
      let resolvedTenant: string | null = null;
      let intendedRole: BusinessRole = 'user';

      if (data.invitation_token && typeof data.invitation_token === 'string' && data.invitation_token.trim().length > 0) {
        const redeemed = tenantInvitationManager.redeemInvitation(data.invitation_token.trim(), {
          expectedEmail: normalizedEmail,
        });
        resolvedTenant = redeemed.tenant_id;
        if (redeemed.intended_role && redeemed.intended_role !== 'anonymous') {
          intendedRole = redeemed.intended_role;
        }

        // Validate that client does not tamper with tenant scope:
        // "valid invitation for Tenant A + request membership in Tenant B -> DENIED"
        if (data.tenant_id && data.tenant_id.trim() !== '' && data.tenant_id.trim() !== redeemed.tenant_id) {
          throw new UnauthorizedAccessError(
            `Access Denied: Invitation is authorized for tenant '${redeemed.tenant_id}', but membership in '${data.tenant_id}' was requested.`
          );
        }

        // Validate that client does not elevate role beyond invitation scope:
        // "normal-user invitation + request admin -> DENIED"
        const requestedRoles = (Array.isArray(data.roles) ? data.roles : data.roles ? [data.roles] : []) as string[];
        if (requestedRoles.length > 0) {
          const unauthorizedRole = requestedRoles.find((r) => r !== intendedRole);
          if (unauthorizedRole) {
            throw new UnauthorizedAccessError(
              `Access Denied: Invitation authorizes role '${intendedRole}', but role '${unauthorizedRole}' was requested.`
            );
          }
        }
      } else {
        // No invitation token supplied:
        // Public self-registration.
        // Client cannot choose its own tenant or role during registration.
        // Caller-supplied roles and tenant_id are strictly ignored.
        // Invariant: CLIENT REQUESTS ROLE != ROLE IS AUTHORIZED
        resolvedTenant = this.determineTenantServerSide({
          email: normalizedEmail,
        });
        intendedRole = 'user';
      }

      roles = [intendedRole];
      if (!isElevatedAdminCaller && !data.invitation_token) {
        tenant_id = null;
      } else {
        tenant_id = resolvedTenant;
      }
    }

    const email_verified = isElevatedAdminCaller ? true : false;
    let verificationToken: string | null = null;
    let verificationExpiresAt: string | null = null;

    if (!email_verified) {
      verificationToken = crypto.randomUUID().replace(/-/g, '');
      verificationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    }

    const record: PrincipalRecord = {
      principal_id,
      email: normalizedEmail,
      hashed_password,
      external_identity_provider_id: data.external_identity_provider_id || null,
      roles,
      tenant_id: tenant_id || null,
      created_at: new Date().toISOString(),
      last_login_at: null,
      email_verified,
      email_verification_token: verificationToken,
      email_verification_expires_at: verificationExpiresAt,
    };

    AuthService.inMemoryPrincipals.set(normalizedEmail, record);

    if (this.dbClient) {
      try {
        const isUuid = (val: unknown): boolean =>
          typeof val === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val);
        const dbTenantId = isUuid(record.tenant_id) ? record.tenant_id : null;

        await this.dbClient.query(
          `INSERT INTO security.principals (principal_id, email, hashed_password, external_identity_provider_id, roles, tenant_id, created_at, email_verified, email_verification_token, email_verification_expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           ON CONFLICT (email) DO NOTHING;`,
          [
            record.principal_id,
            record.email,
            record.hashed_password,
            record.external_identity_provider_id,
            record.roles,
            dbTenantId,
            record.created_at,
            record.email_verified,
            record.email_verification_token,
            record.email_verification_expires_at,
          ]
        );
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        console.warn('[registerPrincipal DB warning]:', errorMsg);
      }
    }

    if (!email_verified && verificationToken) {
      await this.emailSender.sendEmail({
        to: normalizedEmail,
        subject: 'Verify your CAIM account email address',
        text: `Welcome to CAIM Platform!\n\nPlease verify your email by entering this verification code: ${verificationToken}\nOr visit: /verify-email?token=${verificationToken}&email=${encodeURIComponent(normalizedEmail)}\n\nThis verification link expires in 24 hours.`,
        html: `<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;"><h2>Welcome to CAIM Platform</h2><p>Please verify your email address to activate your account.</p><p>Verification code: <strong style="font-family: monospace; font-size: 16px; background: #eee; padding: 4px 8px; border-radius: 4px;">${verificationToken}</strong></p><p><a href="/verify-email?token=${verificationToken}&email=${encodeURIComponent(normalizedEmail)}" style="display: inline-block; padding: 10px 20px; background: #0891b2; color: white; text-decoration: none; border-radius: 6px;">Verify Email</a></p><p style="color: #666; font-size: 12px;">This verification link expires in 24 hours.</p></div>`,
      });
    }

    const { hashed_password: _, email_verification_token: __, ...safePrincipal } = record;
    return safePrincipal;
  }

  /**
   * Dedicated authenticated-admin-only helper for creating a principal with elevated roles
   * or a specific tenant. Requires an authenticated admin caller.
   */
  public async createPrincipalByAdmin(data: {
    email: string;
    password: string;
    roles?: BusinessRole[] | string[];
    tenant_id?: string | null;
    caller: PrincipalContext;
  }): Promise<Omit<PrincipalRecord, 'hashed_password'>> {
    if (!data.caller || !data.caller.is_authenticated || data.caller.roles?.includes('anonymous')) {
      throw new Error('Unauthorized: Admin authentication required to create principals with elevated roles.');
    }

    return this.registerPrincipal({
      email: data.email,
      password: data.password,
      roles: data.roles,
      tenant_id: data.tenant_id,
      caller: data.caller,
      allowElevatedRoles: true,
    });
  }

  /**
   * Verifies an unverified account's email address using the supplied token or code.
   * Supports either { token, email } object or (token, email) arguments.
   */
  public async verifyEmail(
    tokenOrParams: string | { token: string; email?: string },
    emailParam?: string
  ): Promise<{ success: boolean; email: string; message: string }> {
    const token = typeof tokenOrParams === 'string' ? tokenOrParams : tokenOrParams?.token;
    const email = typeof tokenOrParams === 'string' ? emailParam : tokenOrParams?.email;

    const trimmedToken = (token || '').trim();
    if (!trimmedToken) {
      throw new Error('Verification token or code is required.');
    }

    let foundPrincipal: PrincipalRecord | undefined;
    let foundEmail: string | undefined;

    // Search in-memory principals
    for (const [memEmail, p] of AuthService.inMemoryPrincipals.entries()) {
      if (p.email_verification_token && safeCompareSecrets(p.email_verification_token, trimmedToken)) {
        if (!email || email.trim().toLowerCase() === memEmail) {
          foundPrincipal = p;
          foundEmail = memEmail;
          break;
        }
      }
    }

    // If not found in memory and DB is available
    if (!foundPrincipal && this.dbClient) {
      try {
        let queryStr = `SELECT * FROM security.principals WHERE email_verification_token = $1`;
        const qParams: unknown[] = [trimmedToken];
        if (email) {
          queryStr += ` AND email = $2`;
          qParams.push(email.trim().toLowerCase());
        }
        const res = await this.dbClient.query(queryStr, qParams);
        if (res && res.rows && res.rows.length > 0) {
          const row = res.rows[0];
          foundPrincipal = {
            principal_id: String(row.principal_id),
            email: String(row.email),
            hashed_password: String(row.hashed_password),
            external_identity_provider_id: row.external_identity_provider_id ? String(row.external_identity_provider_id) : null,
            roles: Array.isArray(row.roles) ? (row.roles as BusinessRole[]) : ['user'],
            tenant_id: row.tenant_id ? String(row.tenant_id) : null,
            created_at: String(row.created_at),
            last_login_at: row.last_login_at ? String(row.last_login_at) : null,
            email_verified: Boolean(row.email_verified),
            email_verification_token: row.email_verification_token ? String(row.email_verification_token) : null,
            email_verification_expires_at: row.email_verification_expires_at ? String(row.email_verification_expires_at) : null,
          };
          foundEmail = String(row.email);
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        console.warn('[verifyEmail DB query warning]:', errorMsg);
      }
    }

    if (!foundPrincipal || !foundEmail) {
      throw new Error('Invalid or expired email verification token.');
    }

    if (foundPrincipal.email_verification_expires_at) {
      const expires = new Date(foundPrincipal.email_verification_expires_at).getTime();
      if (Date.now() > expires) {
        throw new Error('Email verification token has expired. Please request a new verification link.');
      }
    }

    foundPrincipal.email_verified = true;
    foundPrincipal.email_verification_token = null;
    foundPrincipal.email_verification_expires_at = null;
    if (foundPrincipal.tenant_id === null) {
      const activatedTenant = this.determineTenantServerSide({ email: foundEmail });
      if (activatedTenant) {
        foundPrincipal.tenant_id = activatedTenant;
      }
    }
    AuthService.inMemoryPrincipals.set(foundEmail, foundPrincipal);

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `UPDATE security.principals 
           SET email_verified = true, email_verification_token = NULL, email_verification_expires_at = NULL,
               tenant_id = COALESCE(tenant_id, $2)
           WHERE email = $1;`,
          [foundEmail, foundPrincipal.tenant_id]
        );
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        console.warn('[verifyEmail DB update warning]:', errorMsg);
      }
    }

    return {
      success: true,
      email: foundEmail,
      message: 'Email successfully verified. You may now log in to your account.',
    };
  }

  /**
   * Resends email verification code to an unverified user.
   */
  public async resendVerification(email: string): Promise<{ success: boolean; message: string }> {
    const normalizedEmail = (email || '').trim().toLowerCase();
    if (!normalizedEmail) {
      throw new Error('Email is required.');
    }

    let principal: PrincipalRecord | undefined = AuthService.inMemoryPrincipals.get(normalizedEmail);
    if (!principal && this.dbClient) {
      try {
        const res = await this.dbClient.query('SELECT * FROM security.principals WHERE email = $1;', [normalizedEmail]);
        if (res && res.rows && res.rows.length > 0) {
          principal = parseDbPrincipalRow(res.rows[0]);
          AuthService.inMemoryPrincipals.set(normalizedEmail, principal);
        }
      } catch (err: unknown) {
        // Safe: non-fatal fallback to in-memory store in dev/test when DB tables are not present
        const msg = err instanceof Error ? err.message : String(err);
        console.debug('[AuthService:resendVerification] DB lookup failed, falling back to memory:', msg);
      }
    }

    if (!principal) {
      return { success: true, message: 'If an account exists with this email, a verification link has been sent.' };
    }

    if (principal.email_verified) {
      return { success: true, message: 'Account email is already verified. You may log in directly.' };
    }

    const verificationToken = crypto.randomUUID().replace(/-/g, '');
    const verificationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    principal.email_verification_token = verificationToken;
    principal.email_verification_expires_at = verificationExpiresAt;
    AuthService.inMemoryPrincipals.set(normalizedEmail, principal);

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `UPDATE security.principals 
           SET email_verification_token = $1, email_verification_expires_at = $2 
           WHERE email = $3;`,
          [verificationToken, verificationExpiresAt, normalizedEmail]
        );
      } catch (err: unknown) {
        // Safe in non-production/test environments where table may not exist; in-memory store updated
        const msg = err instanceof Error ? err.message : String(err);
        console.debug('[AuthService:resendVerificationEmail] Non-fatal DB update error, proceeding with memory cache:', msg);
      }
    }

    await this.emailSender.sendEmail({
      to: normalizedEmail,
      subject: 'Verify your CAIM account email address (Resent)',
      text: `Please verify your email by entering verification code: ${verificationToken}\nOr visit: /verify-email?token=${verificationToken}&email=${encodeURIComponent(normalizedEmail)}`,
      html: `<div><h2>Verify your CAIM Email</h2><p>Verification code: <strong>${verificationToken}</strong></p><p><a href="/verify-email?token=${verificationToken}&email=${encodeURIComponent(normalizedEmail)}">Click here to verify</a></p></div>`,
    });

    return { success: true, message: 'Verification email resent successfully.' };
  }

  /**
   * Alias for resendVerification
   */
  public async resendEmailVerification(email: string): Promise<{ success: boolean; message: string }> {
    return this.resendVerification(email);
  }

  /**
   * Authenticates principal with email/password and issues signed JWT + refresh token.
   */
  public async loginWithPassword(credentials: { email: string; password: string }): Promise<LoginResponse> {
    const normalizedEmail = credentials.email.trim().toLowerCase();
    const isProduction = process.env.NODE_ENV === 'production';
    let principal: PrincipalRecord | undefined;

    if (!isProduction) {
      principal = AuthService.inMemoryPrincipals.get(normalizedEmail);
    }

    // If dbClient present, query DB
    if (!principal && this.dbClient) {
      try {
        const res = await this.dbClient.query('SELECT * FROM security.principals WHERE email = $1;', [normalizedEmail]);
        if (res && res.rows && res.rows.length > 0) {
          principal = parseDbPrincipalRow(res.rows[0]);
          if (!isProduction) {
            AuthService.inMemoryPrincipals.set(normalizedEmail, principal);
          }
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (isProduction) {
          throw new Error(`[AuthService] Authentication database query failed in production: ${errorMsg}`);
        }
        // Fallback to in-memory store in non-production
      }
    } else if (isProduction && !this.dbClient) {
      throw new Error('[AuthService] Database client is not configured in production mode.');
    }

    if (!principal) {
      throw new Error('Invalid credentials: user not found.');
    }

    const isValid = await verifyPassword(credentials.password, principal.hashed_password);

    if (!isValid) {
      throw new Error('Invalid credentials: incorrect password.');
    }

    if (principal.email_verified === false) {
      throw new Error('Email not verified. Please verify your email before logging in.');
    }

    principal.last_login_at = new Date().toISOString();

    // Issue JWT access token (15m expiry)
    const access_token = signAccessToken({
      principal_id: principal.principal_id,
      email: principal.email,
      roles: principal.roles,
      tenant_id: principal.tenant_id,
    }, { expiresIn: '15m' });

    // Issue Refresh Token (7 days)
    const { token: refreshToken, tokenHash } = generateRefreshToken();
    const refreshRecord: RefreshTokenRecord = {
      token_id: crypto.randomUUID(),
      principal_id: principal.principal_id,
      token_hash: tokenHash,
      family_id: crypto.randomUUID(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      created_at: new Date().toISOString(),
    };

    AuthService.inMemoryRefreshTokens.set(tokenHash, refreshRecord);

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `INSERT INTO security.refresh_tokens (token_id, principal_id, token_hash, expires_at, created_at)
           VALUES ($1, $2, $3, $4, $5);`,
          [refreshRecord.token_id, refreshRecord.principal_id, refreshRecord.token_hash, refreshRecord.expires_at, refreshRecord.created_at]
        );
        await this.dbClient.query(
          `UPDATE security.principals SET last_login_at = now() WHERE principal_id = $1;`,
          [principal.principal_id]
        );
      } catch (err: unknown) {
        // Non-fatal if table not initialized; in-memory tracking remains valid
        const msg = err instanceof Error ? err.message : String(err);
        console.debug('[AuthService:login] Non-fatal DB refresh token persist error:', msg);
      }
    }

    return {
      access_token,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      principal: {
        principal_id: principal.principal_id,
        email: principal.email,
        roles: principal.roles,
        tenant_id: principal.tenant_id,
        email_verified: principal.email_verified,
      },
    };
  }

  /**
   * Rotates refresh token and issues a new signed JWT access token.
   */
  public async refreshAccessToken(refreshToken: string): Promise<LoginResponse> {
    if (!refreshToken) {
      throw new Error('Missing refresh token.');
    }

    const tokenHash = hashRefreshToken(refreshToken);
    const existing = AuthService.inMemoryRefreshTokens.get(tokenHash);

    if (!existing || existing.revoked_at || new Date(existing.expires_at).getTime() < Date.now()) {
      throw new Error('Invalid, revoked, or expired refresh token.');
    }

    // Revoke old refresh token
    existing.revoked_at = new Date().toISOString();

    // Find principal
    let principal: PrincipalRecord | undefined;
    for (const p of AuthService.inMemoryPrincipals.values()) {
      if (p.principal_id === existing.principal_id) {
        principal = p;
        break;
      }
    }

    if (!principal) {
      throw new Error('Principal associated with refresh token not found.');
    }

    // Issue new access token + new refresh token
    const access_token = signAccessToken({
      principal_id: principal.principal_id,
      email: principal.email,
      roles: principal.roles,
      tenant_id: principal.tenant_id,
    }, { expiresIn: '15m' });

    const { token: newRefreshToken, tokenHash: newTokenHash } = generateRefreshToken();
    const newRefreshRecord: RefreshTokenRecord = {
      token_id: crypto.randomUUID(),
      principal_id: principal.principal_id,
      token_hash: newTokenHash,
      family_id: (existing as any).family_id || crypto.randomUUID(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      created_at: new Date().toISOString(),
    };

    AuthService.inMemoryRefreshTokens.set(newTokenHash, newRefreshRecord);

    return {
      access_token,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: 900,
      principal: {
        principal_id: principal.principal_id,
        email: principal.email,
        roles: principal.roles,
        tenant_id: principal.tenant_id,
        email_verified: principal.email_verified,
      },
    };
  }

  /**
   * Revokes a refresh token session.
   */
  public async revokeSession(refreshToken: string): Promise<boolean> {
    if (!refreshToken) return false;
    const tokenHash = hashRefreshToken(refreshToken);
    const existing = AuthService.inMemoryRefreshTokens.get(tokenHash);
    if (existing) {
      existing.revoked_at = new Date().toISOString();
      return true;
    }
    return false;
  }

  /**
   * Validates password strength against length policy, complexity requirements, and known-compromised dictionaries.
   */
  public static validatePasswordStrength(password: string): { valid: boolean; error?: string } {
    if (!password || typeof password !== 'string') {
      return { valid: false, error: 'Password must be a non-empty string.' };
    }
    if (password.length < 12) {
      return { valid: false, error: 'Password must be at least 12 characters in length.' };
    }
    if (!/[A-Z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one uppercase letter (A-Z).' };
    }
    if (!/[a-z]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one lowercase letter (a-z).' };
    }
    if (!/[0-9]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one numerical digit (0-9).' };
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
      return { valid: false, error: 'Password must contain at least one special character (!@#$%^&*...).' };
    }

    const lower = password.toLowerCase();
    const knownBreached = [
      'admin2026!secureroot#',
      'admin123!secure',
      'password123456',
      'password123!',
      '123456789012',
      'administrator',
      'qwertyuiop12',
      'letmein12345',
      'welcome123456!',
      'rootadmin2026',
    ];

    if (knownBreached.some((b) => lower === b || (b.length >= 8 && lower.includes(b)))) {
      return {
        valid: false,
        error: 'The requested password is in a known-compromised or weak password dictionary. Please choose a strong, unique password.',
      };
    }

    return { valid: true };
  }

  /**
   * Authenticated password rotation for a principal.
   * Re-verifies current password against stored bcrypt hash, validates strength,
   * updates bcrypt hash (10 rounds), and invalidates ALL prior refresh tokens for that principal.
   */
  public async changePassword(input: {
    principalId: string;
    currentPassword: string;
    newPassword: string;
  }): Promise<{ success: boolean; message: string; principalId: string; invalidatedSessionsCount: number }> {
    if (!input.principalId) {
      throw new Error('Missing principal ID.');
    }
    if (!input.currentPassword || !input.newPassword) {
      throw new Error('Both current password and new password are required.');
    }

    // 1. Locate principal
    let principal: PrincipalRecord | undefined;
    for (const p of AuthService.inMemoryPrincipals.values()) {
      if (p.principal_id === input.principalId) {
        principal = p;
        break;
      }
    }

    if (!principal && this.dbClient) {
      try {
        const res = await this.dbClient.query('SELECT * FROM security.principals WHERE principal_id = $1;', [input.principalId]);
        if (res && res.rows && res.rows.length > 0) {
          principal = parseDbPrincipalRow(res.rows[0]);
          AuthService.inMemoryPrincipals.set(principal.email, principal);
        }
      } catch (err: unknown) {
        // Safe: non-fatal fallback in non-production environments when database is unavailable
        const msg = err instanceof Error ? err.message : String(err);
        console.debug('[AuthService:changePassword] DB lookup failed, proceeding with memory check:', msg);
      }
    }

    if (!principal) {
      throw new Error('Principal not found.');
    }

    // 2. Re-verify current password against stored bcrypt hash
    const isCurrentValid = await verifyPassword(input.currentPassword, principal.hashed_password);
    if (!isCurrentValid) {
      throw new Error('Incorrect current password. Re-verification failed.');
    }

    // 3. Prevent setting the exact same password
    if (input.currentPassword === input.newPassword) {
      throw new Error('New password cannot be identical to current password.');
    }

    // 4. Validate new password strength policy & known-breached list
    const validation = AuthService.validatePasswordStrength(input.newPassword);
    if (!validation.valid) {
      throw new Error(validation.error || 'New password does not meet security requirements.');
    }

    // 5. Hash new password with bcrypt (10 rounds)
    const newHashedPassword = await hashPassword(input.newPassword);
    principal.hashed_password = newHashedPassword;

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `UPDATE security.principals SET hashed_password = $1 WHERE principal_id = $2;`,
          [newHashedPassword, principal.principal_id]
        );
      } catch {
        // Continue
      }
    }

    // 6. Invalidate ALL existing refresh tokens for that principal (force re-authentication on other sessions)
    let invalidatedCount = 0;
    const nowIso = new Date().toISOString();
    for (const record of AuthService.inMemoryRefreshTokens.values()) {
      if (record.principal_id === principal.principal_id && !record.revoked_at) {
        record.revoked_at = nowIso;
        invalidatedCount++;
      }
    }

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `UPDATE security.refresh_tokens SET revoked_at = now() WHERE principal_id = $1 AND revoked_at IS NULL;`,
          [principal.principal_id]
        );
      } catch {
        // Continue
      }
    }

    return {
      success: true,
      message: 'Password successfully updated. All prior refresh tokens and active sessions have been invalidated.',
      principalId: principal.principal_id,
      invalidatedSessionsCount: invalidatedCount,
    };
  }

  /**
   * Resolves authoritative entitlements directly from security.principals and associated grant tables.
   * Never trusts client-provided claims or parameters.
   */
  public async resolvePrincipalEntitlements(
    principalId: string,
    fallbackPrincipal?: PrincipalContext
  ): Promise<{
    principal_id: string;
    roles: BusinessRole[];
    grants: string[];
    max_classification_rank: SecurityClassificationRank;
    has_vault_access: boolean;
  }> {
    let roles: BusinessRole[] = [];
    let grants: string[] = [];

    // Service identities (pre-authenticated via internal service shared secret)
    if (principalId.startsWith('service:') || fallbackPrincipal?.is_service) {
      roles = ['admin', 'operator'];
      const maxRank = resolveClassificationClearance(roles, []);
      return {
        principal_id: principalId,
        roles,
        grants: [],
        max_classification_rank: maxRank,
        has_vault_access: true,
      };
    }

    // 1. Check in-memory store for registered principal (only in development and test)
    const isProduction = process.env.NODE_ENV === 'production';
    if (!isProduction) {
      for (const p of AuthService.inMemoryPrincipals.values()) {
        if (p.principal_id === principalId) {
          roles = [...(p.roles || [])];
          break;
        }
      }
    }

    // 2. Query PostgreSQL if database client is available
    if (this.dbClient) {
      try {
        // Query security.principals
        const principalRes = await this.dbClient.query(
          'SELECT roles FROM security.principals WHERE principal_id = $1;',
          [principalId]
        );
        if (principalRes && principalRes.rows && principalRes.rows.length > 0) {
          const dbRoles = principalRes.rows[0].roles;
          if (Array.isArray(dbRoles)) {
            for (const r of dbRoles) {
              if (!roles.includes(r as BusinessRole)) {
                roles.push(r as BusinessRole);
              }
            }
          }
        }

        // Query security.user_roles joined with security.roles
        const userRolesRes = await this.dbClient.query(
          `SELECT r.role_key 
           FROM security.user_roles ur 
           JOIN security.roles r ON ur.role_id = r.role_id 
           WHERE ur.principal_id = $1 AND ur.revoked_at IS NULL;`,
          [principalId]
        );
        if (userRolesRes && userRolesRes.rows) {
          for (const row of userRolesRes.rows) {
            if (row.role_key && !roles.includes(row.role_key as BusinessRole)) {
              roles.push(row.role_key as BusinessRole);
            }
          }
        }

        // Query security.access_grants
        const accessGrantsRes = await this.dbClient.query(
          `SELECT grant_type 
           FROM security.access_grants 
           WHERE principal_id = $1 AND (expires_at IS NULL OR expires_at > now()) AND revoked_at IS NULL;`,
          [principalId]
        );
        if (accessGrantsRes && accessGrantsRes.rows) {
          for (const row of accessGrantsRes.rows) {
            const grantType = typeof row.grant_type === 'string' ? row.grant_type : String(row.grant_type || '');
            if (grantType && !grants.includes(grantType)) {
              grants.push(grantType);
            }
          }
        }

        // Query security.restricted_capability_grants
        const capGrantsRes = await this.dbClient.query(
          `SELECT capability_key 
           FROM security.restricted_capability_grants 
           WHERE principal_id = $1 AND (expires_at IS NULL OR expires_at > now()) AND revoked_at IS NULL;`,
          [principalId]
        );
        if (capGrantsRes && capGrantsRes.rows) {
          for (const row of capGrantsRes.rows) {
            const capKey = typeof row.capability_key === 'string' ? row.capability_key : String(row.capability_key || '');
            if (capKey && !grants.includes(capKey)) {
              grants.push(capKey);
            }
          }
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (isProduction) {
          console.error('[AuthService] FAIL_CLOSED: Database query failed while resolving principal context in production:', errorMsg);
          throw new Error(`[AuthService] Authorization database query failed: ${errorMsg}`);
        }
        // Graceful fallback to in-memory store if tables not yet populated or in mock test env
      }
    } else if (isProduction) {
      console.error('[AuthService] FAIL_CLOSED: Database client missing while resolving principal context in production.');
      throw new Error('[AuthService] Authorization database is unavailable in production mode.');
    }

    // 3. If still empty, fall back to validated fallbackPrincipal roles (if not anonymous)
    if (roles.length === 0 && fallbackPrincipal && fallbackPrincipal.is_authenticated && !fallbackPrincipal.roles.includes('anonymous')) {
      roles = [...fallbackPrincipal.roles];
    }

    if (roles.length === 0) {
      roles = ['user'];
    }

    // Compute classification clearance and vault access from authoritative roles & grants
    const max_classification_rank = resolveClassificationClearance(roles, grants);
    const has_vault_access = isAuthorizedForVault({
      principal_id: principalId,
      is_authenticated: true,
      is_service: false,
      roles,
      grants,
      max_classification_rank,
      accessible_scope_ids: [],
      tenant_id: null,
    });

    return {
      principal_id: principalId,
      roles,
      grants,
      max_classification_rank,
      has_vault_access,
    };
  }
}
