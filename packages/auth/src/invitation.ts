/**
 * CAIM Architecture V2.0.1 — Secure Tenant Invitation Service
 *
 * Enforces cryptographic or opaque DB-backed invitation token authorization.
 * Strict invariants:
 * 1. Rejects forged, unverified, or arbitrary caller-supplied invitation strings.
 * 2. Validates tenant scope, expiration timestamp, intended role, and revocation/use state.
 * 3. Supports single-use redemption and revocation tracking.
 */

import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { BusinessRole, UnauthorizedAccessError } from './types.ts';
import { getInvitationSigningSecret } from './jwt.ts';

export interface TenantInvitationPayload {
  invitation_id: string;
  tenant_id: string;
  intended_role?: BusinessRole;
  email?: string;
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string;
}

export interface TenantInvitationRecord {
  token: string;
  invitation_id: string;
  tenant_id: string;
  intended_role: BusinessRole;
  email?: string | null;
  expires_at: number; // Unix timestamp in ms
  used: boolean;
  revoked: boolean;
  created_at: string;
  created_by?: string;
}

export interface ValidatedInvitation {
  invitation_id: string;
  tenant_id: string;
  intended_role: BusinessRole;
  email?: string | null;
  is_signed: boolean;
}

export interface CreateInvitationOptions {
  tenant_id: string;
  intended_role?: BusinessRole;
  email?: string;
  expiresInSeconds?: number;
  expiresInMs?: number;
  secret?: string;
  created_by?: string;
  creator?: {
    principal_id?: string;
    email?: string;
    roles?: (BusinessRole | string)[];
    is_authenticated?: boolean;
  };
}

export class TenantInvitationManager {
  private static instance: TenantInvitationManager;
  private invitationStore = new Map<string, TenantInvitationRecord>();
  private usedInvitationIds = new Set<string>();
  private revokedInvitationIds = new Set<string>();

  constructor() {
    // Seeded invitations deleted per security requirement P1
  }

  public static getInstance(): TenantInvitationManager {
    if (!TenantInvitationManager.instance) {
      TenantInvitationManager.instance = new TenantInvitationManager();
    }
    return TenantInvitationManager.instance;
  }

  private enforceRoleCap(intendedRole: BusinessRole, creator?: CreateInvitationOptions['creator']): void {
    if (creator) {
      const isCreatorAdmin = Boolean(creator.is_authenticated && creator.roles?.includes('admin'));
      if (intendedRole === 'admin' && !isCreatorAdmin) {
        throw new UnauthorizedAccessError(
          `Cannot create an invitation granting role 'admin': creator is not an authenticated admin.`
        );
      }
    }
  }

  /**
   * Generates a cryptographically signed HMAC-SHA256 invitation token.
   */
  public createSignedInvitation(options: CreateInvitationOptions): string {
    const intended_role = options.intended_role || 'user';
    this.enforceRoleCap(intended_role, options.creator);

    const invitation_id = crypto.randomUUID();
    const expiresIn = options.expiresInSeconds ?? 7 * 24 * 60 * 60; // Default 7 days
    const secret = options.secret || getInvitationSigningSecret();

    const payload: Omit<TenantInvitationPayload, 'iat' | 'exp'> = {
      invitation_id,
      tenant_id: options.tenant_id,
      intended_role,
      email: options.email ? options.email.toLowerCase().trim() : undefined,
    };

    const signOpts: SignOptions = {
      algorithm: 'HS256',
      expiresIn,
      issuer: 'caim-invitation-service',
      audience: 'caim-platform',
    };

    return jwt.sign(payload, secret, signOpts);
  }

  /**
   * Creates and registers an opaque DB-backed invitation record.
   */
  public createOpaqueInvitation(options: CreateInvitationOptions): TenantInvitationRecord {
    const intended_role = options.intended_role || 'user';
    this.enforceRoleCap(intended_role, options.creator);

    const rawId = crypto.randomBytes(32).toString('hex');
    const token = `inv_${rawId}`;
    const expires_at = Date.now() + (options.expiresInMs ?? 7 * 24 * 60 * 60 * 1000);

    const record: TenantInvitationRecord = {
      token,
      invitation_id: rawId,
      tenant_id: options.tenant_id,
      intended_role,
      email: options.email ? options.email.toLowerCase().trim() : null,
      expires_at,
      used: false,
      revoked: false,
      created_at: new Date().toISOString(),
      created_by: options.created_by || 'admin',
    };

    this.invitationStore.set(token, record);
    return record;
  }

  /**
   * Validates an invitation token without marking it as consumed.
   */
  public validateInvitation(
    token: string,
    options?: { secret?: string; expectedEmail?: string }
  ): ValidatedInvitation {
    if (!token || typeof token !== 'string' || token.trim().length === 0) {
      throw new UnauthorizedAccessError('Invitation token cannot be empty.');
    }

    const trimmed = token.trim();

    // 1. Check if token is a cryptographically signed JWT (3 segments separated by dots)
    const isJwtFormat = trimmed.split('.').length === 3;
    if (isJwtFormat) {
      const secret = options?.secret || getInvitationSigningSecret();
      let decoded: TenantInvitationPayload;

      try {
        const verifyOpts: VerifyOptions = {
          algorithms: ['HS256'],
          issuer: 'caim-invitation-service',
          audience: 'caim-platform',
        };
        decoded = jwt.verify(trimmed, secret, verifyOpts) as TenantInvitationPayload;
      } catch (err: unknown) {
        if (err instanceof Error && err.name === 'TokenExpiredError') {
          throw new UnauthorizedAccessError('Invitation token has expired.');
        }
        throw new UnauthorizedAccessError('Forged or invalid cryptographic invitation token.');
      }

      if (!decoded.tenant_id) {
        throw new UnauthorizedAccessError('Invitation token contains no authorized tenant scope.');
      }

      // Check revocation or single-use state
      if (this.revokedInvitationIds.has(decoded.invitation_id)) {
        throw new UnauthorizedAccessError('Invitation token has been revoked.');
      }

      if (this.usedInvitationIds.has(decoded.invitation_id)) {
        throw new UnauthorizedAccessError('Invitation token has already been used.');
      }

      // Optional email recipient check
      if (decoded.email && options?.expectedEmail) {
        const normExpected = options.expectedEmail.toLowerCase().trim();
        if (decoded.email.toLowerCase().trim() !== normExpected) {
          throw new UnauthorizedAccessError(
            `Invitation token is restricted to '${decoded.email}' but presented by '${options.expectedEmail}'.`
          );
        }
      }

      return {
        invitation_id: decoded.invitation_id,
        tenant_id: decoded.tenant_id,
        intended_role: (decoded.intended_role as BusinessRole) || 'user',
        email: decoded.email || null,
        is_signed: true,
      };
    }

    // 2. Opaque token lookup in registered database/in-memory store
    const record = this.invitationStore.get(trimmed);
    if (!record) {
      // SECURITY INVARIANT:
      // Never derive tenant from unverified substring splitting or prefix matching.
      // Any unregistered opaque token is strictly rejected as forged.
      throw new UnauthorizedAccessError(
        `Forged or unrecognized invitation token: '${trimmed}'. No valid invitation record found.`
      );
    }

    // Check revocation
    if (record.revoked || this.revokedInvitationIds.has(record.invitation_id)) {
      throw new UnauthorizedAccessError('Invitation token has been revoked.');
    }

    // Check single-use state
    if (record.used || this.usedInvitationIds.has(record.invitation_id)) {
      throw new UnauthorizedAccessError('Invitation token has already been used.');
    }

    // Check expiration
    if (Date.now() > record.expires_at) {
      throw new UnauthorizedAccessError('Invitation token has expired.');
    }

    // Optional email recipient check
    if (record.email && options?.expectedEmail) {
      const normExpected = options.expectedEmail.toLowerCase().trim();
      if (record.email.toLowerCase().trim() !== normExpected) {
        throw new UnauthorizedAccessError(
          `Invitation token is restricted to '${record.email}' but presented by '${options.expectedEmail}'.`
        );
      }
    }

    return {
      invitation_id: record.invitation_id,
      tenant_id: record.tenant_id,
      intended_role: record.intended_role,
      email: record.email,
      is_signed: false,
    };
  }

  /**
   * Redeems an invitation token, enforcing validity and marking it as used.
   */
  public redeemInvitation(
    token: string,
    options?: { secret?: string; expectedEmail?: string }
  ): ValidatedInvitation {
    const validated = this.validateInvitation(token, options);

    // Mark as consumed
    this.usedInvitationIds.add(validated.invitation_id);

    const record = this.invitationStore.get(token.trim());
    if (record) {
      record.used = true;
    }

    return validated;
  }

  /**
   * Revokes an invitation so it cannot be redeemed.
   */
  public revokeInvitation(invitationIdOrToken: string): boolean {
    const trimmed = invitationIdOrToken.trim();
    const record = this.invitationStore.get(trimmed);

    if (record) {
      record.revoked = true;
      this.revokedInvitationIds.add(record.invitation_id);
      return true;
    }

    this.revokedInvitationIds.add(trimmed);
    return true;
  }

  /**
   * Resets the invitation store (for test suite isolation).
   */
  public resetForTesting(): void {
    this.invitationStore.clear();
    this.usedInvitationIds.clear();
    this.revokedInvitationIds.clear();
  }
}

export const tenantInvitationManager = TenantInvitationManager.getInstance();
