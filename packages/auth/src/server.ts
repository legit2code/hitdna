import { PrincipalContext, BusinessRole, ServiceIdentity, UnauthorizedAccessError, ScopeBoundaryViolationError } from './types.ts';
import { resolvePrincipalClaims, createAnonymousPrincipal } from './claims.ts';
import { verifyAccessToken, getJwtSecret } from './jwt.ts';
import { serviceAccountRegistry, ServiceAccountRegistry } from './service-account.ts';
import type { DatabaseClient } from '@caim/db';

export interface SupabaseServerAuthConfig {
  jwtSecret?: string;
  serviceSecret?: string;
  discoveryServiceToken?: string;
  allowDevBypass?: boolean;
  serviceTenantScopes?: Record<string, string[]>;
  dbClient?: DatabaseClient;
  supabaseServiceKey?: string;
}

export class SupabaseServerAuth {
  private jwtSecret: string;
  private serviceSecret?: string;
  private discoveryServiceToken?: string;
  private serviceTenantScopes: Record<string, string[]>;
  private allowDevBypass: boolean;
  private registry: ServiceAccountRegistry;

  constructor(config?: Partial<SupabaseServerAuthConfig>) {
    this.jwtSecret = config?.jwtSecret || getJwtSecret();
    this.serviceSecret = config?.serviceSecret || process.env.SERVICE_TO_SERVICE_SECRET;
    this.discoveryServiceToken = config?.discoveryServiceToken || process.env.CAIM_DISCOVERY_SERVICE_TOKEN;
    this.serviceTenantScopes = config?.serviceTenantScopes || this.resolveConfiguredTenantScopes();
    this.registry = ServiceAccountRegistry.getInstance(config?.dbClient);

    // Auth bypass is strictly forbidden in production or staging
    const isProductionLike = process.env.APP_ENV === 'production' || process.env.APP_ENV === 'staging' || process.env.NODE_ENV === 'production';
    this.allowDevBypass = !isProductionLike && (config?.allowDevBypass ?? false);
  }

  private resolveConfiguredTenantScopes(): Record<string, string[]> {
    const raw = process.env.SERVICE_AUTHORIZED_TENANTS;
    if (raw) {
      try {
        return JSON.parse(raw);
      } catch {
        return {};
      }
    }
    // R04 Task 4: Removed test default {'*': ['*']} from production code
    return {};
  }

  /**
   * Resolves caller identity and roles from verified JWT token or verified service credentials.
   * INVARIANT: Identity comes strictly from verified credentials and DB records, never request headers.
   * Client-supplied role headers or service identity headers are NEVER trusted.
   */
  public async authenticateRequest(headers: Record<string, string | string[] | undefined>): Promise<PrincipalContext> {
    const authHeader = headers['authorization'] || headers['Authorization'];
    const tenantHeader = headers['x-tenant-id'] || headers['X-Tenant-Id'];
    const bypassHeader = headers['x-bypass-auth'] || headers['X-Bypass-Auth'];

    // 1. Bearer credential extraction (Service Token or Asymmetric JWT)
    if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7).trim();

      // Check service token credential in ServiceAccountRegistry
      const serviceAccount = await this.registry.authenticateServiceToken(
        token,
        this.discoveryServiceToken,
        this.serviceSecret
      );

      if (serviceAccount) {
        const requestedTenantId = typeof tenantHeader === 'string' ? tenantHeader : null;
        const validatedTenantId = this.registry.validateTenantScope(serviceAccount, requestedTenantId);

        return resolvePrincipalClaims({
          principal_id: `service:${serviceAccount.name}`,
          is_service: true,
          service_name: serviceAccount.name as ServiceIdentity,
          tenant_id: validatedTenantId,
          capabilities: serviceAccount.capabilities,
          authentication_method: 'service_token',
        });
      }

      // Check standard Asymmetric JWT
      try {
        const decoded = verifyAccessToken(token);

        return resolvePrincipalClaims({
          principal_id: decoded.sub,
          roles: decoded.roles && Array.isArray(decoded.roles) ? decoded.roles : ['user'],
          capabilities: decoded.capabilities,
          tenant_id: decoded.tenant_id ?? null,
          accessible_scope_ids: decoded.accessible_scope_ids,
          is_service: decoded.is_service ?? false,
          service_name: decoded.service_name,
          authentication_method: 'bearer_jwt',
          token_issuer: decoded.iss,
          token_audience: decoded.aud,
          token_expires_at: decoded.exp,
        });
      } catch {
        // Token verification failed (invalid signature, expired, tampered, revoked)
        // Strictly return unauthenticated anonymous context — do not grant any roles
        return createAnonymousPrincipal();
      }
    }

    // 2. Optional Dev Bypass Header (STRICTLY gated out in production and staging)
    const isProductionLike = process.env.APP_ENV === 'production' || process.env.APP_ENV === 'staging' || process.env.NODE_ENV === 'production';
    if (!isProductionLike && this.allowDevBypass && bypassHeader === 'true') {
      return resolvePrincipalClaims({
        principal_id: 'dev_bypass_principal',
        roles: ['user'],
        authentication_method: 'dev_bypass',
      });
    }

    // 3. Fallback to anonymous unauthenticated caller
    return createAnonymousPrincipal();
  }
}

export function createServerAuthHelper(config?: Partial<SupabaseServerAuthConfig>): SupabaseServerAuth {
  return new SupabaseServerAuth(config);
}
