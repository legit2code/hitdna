/**
 * Enterprise JSON Web Token (JWT) Service
 * Asymmetric RS256 signing with kid, JWKS-style key sets supporting rotation,
 * jti revocation tracking, principal token_version validation, and refresh token families.
 */

import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { BusinessRole, ServiceIdentity } from './types.ts';
import type { DatabaseClient } from '@caim/db';

export const DEFAULT_ACCESS_TOKEN_EXPIRY = '15m'; // 15 minutes TTL per R04 Task 2

export const INSECURE_SECRET_BLOCKLIST = [
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

let ephemeralJwtSecret: string | null = null;
let ephemeralInvitationSecret: string | null = null;

export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  const isProduction = process.env.NODE_ENV === 'production' || process.env.APP_ENV === 'production';

  if (secret) {
    const trimmed = secret.trim();
    const isBlocked = INSECURE_SECRET_BLOCKLIST.some(
      (b) => b.toLowerCase() === trimmed.toLowerCase()
    );

    if (isBlocked) {
      if (isProduction) {
        throw new Error(
          `[FATAL SECURITY CONFIGURATION] JWT_SECRET matches blocked insecure default secret: '${trimmed}'. Production startup aborted.`
        );
      }
    } else if (trimmed.length < 32) {
      if (isProduction) {
        throw new Error(
          `[FATAL SECURITY CONFIGURATION] JWT_SECRET must be at least 32 characters long in production (current length: ${trimmed.length}). Production startup aborted.`
        );
      }
    } else {
      return trimmed;
    }
  }

  if (isProduction) {
    throw new Error(
      `[FATAL SECURITY CONFIGURATION] Mandatory environment variable JWT_SECRET is missing or empty in production mode. Production startup aborted.`
    );
  }

  // Development/Test only: generate per-process ephemeral secret
  if (!ephemeralJwtSecret) {
    ephemeralJwtSecret = crypto.randomBytes(32).toString('hex');
    console.warn(
      `[SECURITY WARNING] JWT_SECRET is not configured or weak in ${process.env.NODE_ENV || 'development'}. Generated ephemeral per-process signing secret.`
    );
  }
  return ephemeralJwtSecret;
}

export function getInvitationSigningSecret(): string {
  const secret = process.env.INVITATION_SIGNING_SECRET;
  const isProduction = process.env.NODE_ENV === 'production' || process.env.APP_ENV === 'production';
  const jwtSecret = process.env.JWT_SECRET;

  if (secret) {
    const trimmed = secret.trim();
    const isBlocked = INSECURE_SECRET_BLOCKLIST.some(
      (b) => b.toLowerCase() === trimmed.toLowerCase()
    );

    if (isBlocked) {
      if (isProduction) {
        throw new Error(
          `[FATAL SECURITY CONFIGURATION] INVITATION_SIGNING_SECRET matches blocked insecure default secret: '${trimmed}'. Production startup aborted.`
        );
      }
    } else if (trimmed.length < 32) {
      if (isProduction) {
        throw new Error(
          `[FATAL SECURITY CONFIGURATION] INVITATION_SIGNING_SECRET must be at least 32 characters long in production (current length: ${trimmed.length}). Production startup aborted.`
        );
      }
    } else if (jwtSecret && trimmed === jwtSecret.trim()) {
      if (isProduction) {
        throw new Error(
          `[FATAL SECURITY CONFIGURATION] INVITATION_SIGNING_SECRET must not reuse JWT_SECRET. A dedicated separate secret is required. Production startup aborted.`
        );
      }
    } else {
      return trimmed;
    }
  }

  if (isProduction) {
    throw new Error(
      `[FATAL SECURITY CONFIGURATION] Mandatory environment variable INVITATION_SIGNING_SECRET is missing or empty in production mode. Production startup aborted.`
    );
  }

  // Development/Test only: generate per-process ephemeral secret
  if (!ephemeralInvitationSecret) {
    ephemeralInvitationSecret = crypto.randomBytes(32).toString('hex');
    console.warn(
      `[SECURITY WARNING] INVITATION_SIGNING_SECRET is not configured or weak in ${process.env.NODE_ENV || 'development'}. Generated ephemeral per-process invitation secret.`
    );
  }
  return ephemeralInvitationSecret;
}

// Backward-compatible fallback export
export const DEFAULT_JWT_SECRET = process.env.NODE_ENV === 'production' ? '' : getJwtSecret();

export interface AsymmetricKeyEntry {
  kid: string;
  publicKey: string; // PEM format
  privateKey?: string; // PEM format (present if used for signing)
  algorithm: 'RS256';
  status: 'ACTIVE' | 'ROTATING' | 'RETIRED';
}

/**
 * Key Manager supporting multiple keys with kid lookup for smooth key rotation.
 */
export class JwtKeyManager {
  private static instance: JwtKeyManager;
  private keys = new Map<string, AsymmetricKeyEntry>();
  private activeSigningKid: string;

  constructor() {
    this.activeSigningKid = process.env.JWT_SIGNING_KID || 'caim-auth-key-v1';
    this.initializeKeys();
  }

  public static getInstance(): JwtKeyManager {
    if (!JwtKeyManager.instance) {
      JwtKeyManager.instance = new JwtKeyManager();
    }
    return JwtKeyManager.instance;
  }

  private initializeKeys(): void {
    const configuredPriv = process.env.JWT_SIGNING_PRIVATE_KEY || process.env.SIGNING_PRIVATE_KEY;
    const configuredPub = process.env.JWT_SIGNING_PUBLIC_KEY || process.env.SIGNING_PUBLIC_KEY;

    if (configuredPriv && configuredPub) {
      this.keys.set(this.activeSigningKid, {
        kid: this.activeSigningKid,
        privateKey: configuredPriv,
        publicKey: configuredPub,
        algorithm: 'RS256',
        status: 'ACTIVE',
      });
      return;
    }

    // In non-production (development / test), generate an ephemeral RSA 2048 keypair
    const isProductionLike = process.env.APP_ENV === 'production' || process.env.APP_ENV === 'staging';
    if (!isProductionLike) {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      this.keys.set(this.activeSigningKid, {
        kid: this.activeSigningKid,
        privateKey,
        publicKey,
        algorithm: 'RS256',
        status: 'ACTIVE',
      });
    }
  }

  public addKey(entry: AsymmetricKeyEntry): void {
    this.keys.set(entry.kid, entry);
  }

  public getKey(kid: string): AsymmetricKeyEntry | undefined {
    return this.keys.get(kid);
  }

  public getActiveSigningKey(): AsymmetricKeyEntry {
    const key = this.keys.get(this.activeSigningKid);
    if (!key || !key.privateKey) {
      throw new Error(
        `[JwtKeyManager] No active asymmetric signing key available for kid '${this.activeSigningKid}'.`
      );
    }
    return key;
  }

  public setActiveSigningKid(kid: string): void {
    if (!this.keys.has(kid)) {
      throw new Error(`[JwtKeyManager] Cannot set unknown key ID '${kid}' as active.`);
    }
    this.activeSigningKid = kid;
  }

  public getPublicJwks(): Array<{ kid: string; alg: string; kty: string; use: string; publicKey: string }> {
    return Array.from(this.keys.values()).map((k) => ({
      kid: k.kid,
      alg: k.algorithm,
      kty: 'RSA',
      use: 'sig',
      publicKey: k.publicKey,
    }));
  }

  public clear(): void {
    this.keys.clear();
    this.initializeKeys();
  }
}

export const jwtKeyManager = JwtKeyManager.getInstance();

export interface JwtPrincipalClaims {
  sub: string; // principal_id
  email: string;
  roles: BusinessRole[];
  capabilities?: string[];
  tenant_id?: string | null;
  accessible_scope_ids?: string[];
  is_service?: boolean;
  service_name?: ServiceIdentity;
  token_version?: number;
  jti?: string;
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
}

export interface SignTokenOptions {
  kid?: string;
  expiresIn?: SignOptions['expiresIn'];
  issuer?: string;
  audience?: string;
  secret?: string;
}

/**
 * Constant-time digest comparison to prevent timing side-channel attacks on secrets and tokens.
 */
export function safeCompareSecrets(a: string, b: string): boolean {
  if (!a || !b) return false;
  const hashA = crypto.createHash('sha256').update(String(a)).digest();
  const hashB = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// In-memory revocation and version stores for dev/test environments without live DB
const inMemoryRevokedJtis = new Set<string>();
const inMemoryPrincipalTokenVersions = new Map<string, number>();

/**
 * Checks if a JWT token has been explicitly revoked by its unique JTI.
 */
export async function isTokenRevoked(jti: string, dbClient?: DatabaseClient): Promise<boolean> {
  if (!jti) return false;
  if (inMemoryRevokedJtis.has(jti)) return true;

  if (dbClient) {
    try {
      const res = await dbClient.query(
        'SELECT jti FROM security.revoked_tokens WHERE jti = $1 AND expires_at > now() LIMIT 1;',
        [jti]
      );
      if (res && res.rows && res.rows.length > 0) {
        inMemoryRevokedJtis.add(jti);
        return true;
      }
    } catch {
      // Fall through to memory check if table unavailable
    }
  }
  return false;
}

/**
 * Revokes a token by recording its JTI in the revocation blacklist.
 */
export async function revokeTokenByJti(
  jti: string,
  principalId: string,
  expiresAt: Date,
  reason?: string,
  dbClient?: DatabaseClient
): Promise<void> {
  if (!jti) return;
  inMemoryRevokedJtis.add(jti);

  if (dbClient) {
    try {
      await dbClient.query(
        `INSERT INTO security.revoked_tokens (jti, principal_id, expires_at, reason)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (jti) DO NOTHING;`,
        [jti, principalId, expiresAt.toISOString(), reason || 'User logout or security revocation']
      );
    } catch {
      // Handled in memory
    }
  }
}

/**
 * Resolves current active token version for a principal.
 */
export async function getPrincipalTokenVersion(principalId: string, dbClient?: DatabaseClient): Promise<number> {
  if (dbClient) {
    try {
      const res = await dbClient.query(
        'SELECT token_version FROM security.principals WHERE principal_id = $1 LIMIT 1;',
        [principalId]
      );
      if (res && res.rows && res.rows.length > 0 && res.rows[0].token_version !== undefined) {
        const v = parseInt(String(res.rows[0].token_version), 10);
        inMemoryPrincipalTokenVersions.set(principalId, v);
        return v;
      }
    } catch {
      // Fall through to memory store
    }
  }
  return inMemoryPrincipalTokenVersions.get(principalId) || 1;
}

/**
 * Increments principal's token version, immediately invalidating all outstanding JWTs issued with older versions.
 */
export async function incrementPrincipalTokenVersion(
  principalId: string,
  dbClient?: DatabaseClient
): Promise<number> {
  const current = await getPrincipalTokenVersion(principalId, dbClient);
  const nextVersion = current + 1;
  inMemoryPrincipalTokenVersions.set(principalId, nextVersion);

  if (dbClient) {
    try {
      await dbClient.query(
        'UPDATE security.principals SET token_version = $1 WHERE principal_id = $2;',
        [nextVersion, principalId]
      );
    } catch {
      // Memory store already updated
    }
  }
  return nextVersion;
}

/**
 * Signs a short-lived access token using asymmetric RS256 with kid and jti.
 */
export function signAccessToken(
  claims: {
    principal_id: string;
    email: string;
    roles: BusinessRole[];
    capabilities?: string[];
    tenant_id?: string | null;
    accessible_scope_ids?: string[];
    is_service?: boolean;
    service_name?: ServiceIdentity;
    token_version?: number;
    jti?: string;
  },
  options?: SignTokenOptions
): string {
  if (options?.secret) {
    const jti = claims.jti || crypto.randomUUID();
    const tokenVersion = claims.token_version ?? 1;
    const payload: Omit<JwtPrincipalClaims, 'iat' | 'exp'> = {
      sub: claims.principal_id,
      email: claims.email,
      roles: claims.roles && claims.roles.length > 0 ? claims.roles : ['user'],
      capabilities: claims.capabilities,
      tenant_id: claims.tenant_id || null,
      accessible_scope_ids: claims.accessible_scope_ids || ['00000000-0000-0000-0000-000000000001'],
      is_service: claims.is_service ?? false,
      service_name: claims.service_name,
      token_version: tokenVersion,
      jti,
    };
    return jwt.sign(payload, options.secret, {
      algorithm: 'HS256',
      expiresIn: options?.expiresIn ?? DEFAULT_ACCESS_TOKEN_EXPIRY,
      issuer: options?.issuer || 'caim-auth-service',
      audience: options?.audience || 'caim-platform',
    });
  }

  const activeKey = options?.kid ? jwtKeyManager.getKey(options.kid) : jwtKeyManager.getActiveSigningKey();
  if (!activeKey || !activeKey.privateKey) {
    throw new Error(`Signing key with kid '${options?.kid || 'active'}' is not available for signing.`);
  }

  const jti = claims.jti || crypto.randomUUID();
  const tokenVersion = claims.token_version ?? 1;

  const payload: Omit<JwtPrincipalClaims, 'iat' | 'exp'> = {
    sub: claims.principal_id,
    email: claims.email,
    roles: claims.roles && claims.roles.length > 0 ? claims.roles : ['user'],
    capabilities: claims.capabilities,
    tenant_id: claims.tenant_id || null,
    accessible_scope_ids: claims.accessible_scope_ids || ['00000000-0000-0000-0000-000000000001'],
    is_service: claims.is_service ?? false,
    service_name: claims.service_name,
    token_version: tokenVersion,
    jti,
  };

  const signOpts: SignOptions = {
    algorithm: 'RS256',
    keyid: activeKey.kid,
    expiresIn: options?.expiresIn ?? DEFAULT_ACCESS_TOKEN_EXPIRY,
    issuer: options?.issuer || 'caim-auth-service',
    audience: options?.audience || 'caim-platform',
  };

  return jwt.sign(payload, activeKey.privateKey, signOpts);
}

/**
 * Strictly verifies JWT signature, kid, algorithm, and expiry.
 * Strictly rejects 'none' algorithm and public key confusion attacks (e.g. HS256).
 */
export function verifyAccessToken(token: string): JwtPrincipalClaims {
  if (!token || typeof token !== 'string') {
    throw new Error('Missing or invalid token string.');
  }

  // 1. Decode header without verification to check alg and kid
  const unverified = jwt.decode(token, { complete: true });
  if (!unverified || typeof unverified !== 'object' || !unverified.header) {
    throw new Error('Malformed or unparseable JWT.');
  }

  const header = unverified.header;

  // Strict check: alg must be RS256
  if (!header.alg || header.alg === 'none' || header.alg !== 'RS256') {
    throw new Error(`Invalid or rejected algorithm: '${header.alg}'. Only RS256 is accepted.`);
  }

  // Strict check: kid must be present and known
  if (!header.kid) {
    throw new Error('Missing key ID (kid) in token header.');
  }

  const keyEntry = jwtKeyManager.getKey(header.kid);
  if (!keyEntry || !keyEntry.publicKey) {
    throw new Error(`Unknown or unregistered key ID (kid): '${header.kid}'.`);
  }

  const verifyOpts: VerifyOptions = {
    algorithms: ['RS256'],
    issuer: 'caim-auth-service',
    audience: 'caim-platform',
  };

  return jwt.verify(token, keyEntry.publicKey, verifyOpts) as JwtPrincipalClaims;
}

/**
 * Asynchronously verifies JWT token along with jti revocation check and principal token_version check.
 */
export async function verifyAccessTokenAsync(
  token: string,
  dbClient?: DatabaseClient
): Promise<JwtPrincipalClaims> {
  const decoded = verifyAccessToken(token);

  // Check revocation of JTI
  if (decoded.jti) {
    const isRevoked = await isTokenRevoked(decoded.jti, dbClient);
    if (isRevoked) {
      throw new Error(`Token with jti '${decoded.jti}' has been revoked.`);
    }
  }

  // Check stale token_version
  if (decoded.sub && decoded.token_version !== undefined) {
    const currentVersion = await getPrincipalTokenVersion(decoded.sub, dbClient);
    if (decoded.token_version < currentVersion) {
      throw new Error(
        `Stale token version (${decoded.token_version} < ${currentVersion}). All prior sessions have been invalidated.`
      );
    }
  }

  return decoded;
}

export interface RefreshTokenResult {
  token: string;
  tokenHash: string;
  familyId: string;
}

/**
 * Generates an opaque cryptographically secure refresh token + sha256 hash + family_id.
 */
export function generateRefreshToken(existingFamilyId?: string): RefreshTokenResult {
  const token = `rt_${crypto.randomBytes(32).toString('hex')}`;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const familyId = existingFamilyId || crypto.randomUUID();
  return { token, tokenHash, familyId };
}

/**
 * Computes sha256 hash of a refresh token string for lookup.
 */
export function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Resets in-memory revocation and version stores (for test isolation).
 */
export function resetJwtRevocationStoresForTesting(): void {
  inMemoryRevokedJtis.clear();
  inMemoryPrincipalTokenVersions.clear();
}
