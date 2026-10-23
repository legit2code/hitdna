import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank, 
  ServiceIdentity, 
  UnauthorizedAccessError, 
  UnauthorizedVaultAccessError, 
  ScopeBoundaryViolationError 
} from './types.ts';
import { isAuthorizedForVault } from './vault.ts';
import { CapabilityGrantService, RestrictedCapabilityGrant } from './capability.ts';

export function requireAuth(context: PrincipalContext): void {
  if (!context.is_authenticated) {
    throw new UnauthorizedAccessError('Authentication required: principal is anonymous.');
  }
}

export function requireRole(context: PrincipalContext, allowedRoles: BusinessRole[]): void {
  if (context.is_override_active || context.roles.includes('admin')) {
    return;
  }
  const hasRole = allowedRoles.some(r => context.roles.includes(r));
  if (!hasRole) {
    throw new UnauthorizedAccessError(
      `Role authorization failed: principal '${context.principal_id}' lacks required role (${allowedRoles.join(', ')}). Has: ${context.roles.join(', ')}`
    );
  }
}

export function requireClassification(context: PrincipalContext, requiredRank: SecurityClassificationRank): void {
  if (context.is_override_active) {
    return;
  }
  if (requiredRank >= SecurityClassificationRank.VAULT_RESTRICTED && !isAuthorizedForVault(context)) {
    throw new UnauthorizedVaultAccessError(
      `Vault boundary violation: principal '${context.principal_id}' cannot access VAULT_RESTRICTED records.`
    );
  }
  if (context.max_classification_rank < requiredRank) {
    throw new UnauthorizedAccessError(
      `Insufficient security clearance: principal rank is ${context.max_classification_rank}, required rank is ${requiredRank}.`
    );
  }
}

export function requireScope(context: PrincipalContext, targetScopeId: string): void {
  if (context.is_override_active || context.roles.includes('admin')) {
    return;
  }
  if (!context.accessible_scope_ids.includes(targetScopeId)) {
    throw new ScopeBoundaryViolationError(
      `Tenant/Scope violation: principal '${context.principal_id}' has no grant for scope '${targetScopeId}'.`
    );
  }
}

export function requireServiceIdentity(context: PrincipalContext, allowedServices: ServiceIdentity[]): void {
  if (context.is_override_active) {
    return;
  }
  if (!context.is_service || !context.service_name || !allowedServices.includes(context.service_name)) {
    throw new UnauthorizedAccessError(
      `Service identity violation: caller is not an authorized backend worker (${allowedServices.join(', ')}).`
    );
  }
}

export function requireGrant(context: PrincipalContext, grantType: string): void {
  if (context.is_override_active || context.roles.includes('admin')) {
    return;
  }
  if (!context.grants.includes(grantType)) {
    throw new UnauthorizedAccessError(
      `Access grant missing: principal '${context.principal_id}' lacks grant '${grantType}'.`
    );
  }
}

/**
 * Dedicated per-principal capability grant check (NON-ROLE-BASED).
 * Admin role alone does NOT confer capability access; must have an active grant row.
 */
export async function requireCapabilityGrant(
  context: PrincipalContext,
  capabilityKey: string | string[],
  options: {
    techniqueCategory?: string;
    grantService?: CapabilityGrantService;
  } = {}
): Promise<void> {
  if (!context.is_authenticated || !context.principal_id || context.principal_id === 'anonymous') {
    throw new UnauthorizedAccessError('Authentication required: principal is anonymous.');
  }

  // Capability grants are strictly per-principal and NEVER implicitly granted by admin role alone
  const service = options.grantService || new CapabilityGrantService();

  const keys = Array.isArray(capabilityKey) ? capabilityKey : [capabilityKey];

  // 1. Generic capability key check against active grants
  const activeGrants: RestrictedCapabilityGrant[] = await service.getActiveGrantsForPrincipal(context.principal_id);
  const hasKey = activeGrants.some((g: RestrictedCapabilityGrant) => keys.includes(g.capability_key));
  if (hasKey) {
    return;
  }

  // 2. If checking composer capability specifically (e.g. technique categories)
  if (keys.includes('composer:full_access') || keys.includes('composer:restricted_access')) {
    const access = await service.checkComposerAccess(context.principal_id, options.techniqueCategory);
    if (access.allowed) {
      return;
    }
    throw new UnauthorizedAccessError(
      access.reason || `Principal '${context.principal_id}' lacks active capability grant for ${keys.join(' or ')}.`
    );
  }

  throw new UnauthorizedAccessError(
    `Principal '${context.principal_id}' lacks active restricted capability grant for '${keys.join(', ')}'.`
  );
}

/**
 * Resolves and strictly validates authorized tenant context for an authenticated principal.
 * 
 * Required Invariants:
 * 1. An unauthenticated or anonymous principal CANNOT access tenant-scoped operations.
 * 2. Client-supplied tenant identifiers (e.g. from headers, params, query, or body) CANNOT be trusted blindly.
 * 3. Client supplies tenant ID !== Client is authorized for tenant.
 * 4. If requestedTenantId is supplied, it MUST match the principal's verified tenant or active tenant memberships.
 * 5. If requestedTenantId is omitted, defaults strictly to the principal's authoritative tenant.
 * 6. If the principal has NO tenant and the operation requires one, fail closed immediately.
 */
export function resolveAuthorizedTenant(
  principal?: PrincipalContext | null,
  requestedTenantId?: string | null
): string {
  if (!principal || !principal.is_authenticated || principal.roles?.includes('anonymous')) {
    throw new UnauthorizedAccessError('NO AUTHENTICATED PRINCIPAL: Authentication required for tenant operations.');
  }

  const cleanRequested = (requestedTenantId && typeof requestedTenantId === 'string' && requestedTenantId.trim().length > 0)
    ? requestedTenantId.trim()
    : null;

  const rawPrincipalTenant = principal.tenant_id ?? principal.tenantId ?? null;
  const principalTenant = (rawPrincipalTenant && typeof rawPrincipalTenant === 'string' && rawPrincipalTenant.trim().length > 0)
    ? rawPrincipalTenant.trim()
    : null;

  const isSystemAuthorized = principal.roles?.includes('system_admin') ||
    (principal.is_service && principal.accessible_scope_ids?.includes('*')) ||
    principal.principal_id === 'system' ||
    principal.principal_id === 'caim-system-worker';

  if (cleanRequested) {
    if (isSystemAuthorized) {
      return cleanRequested;
    }

    if (principalTenant && principalTenant.toLowerCase() === cleanRequested.toLowerCase()) {
      return principalTenant;
    }

    const memberships = principal.tenant_memberships;
    const hasMembership = memberships?.some(
      m => m.tenant_id?.toLowerCase() === cleanRequested.toLowerCase() && m.status !== 'SUSPENDED'
    );
    if (hasMembership) {
      return cleanRequested;
    }

    throw new ScopeBoundaryViolationError(
      `NO AUTHORIZED TENANT CONTEXT: Authenticated principal '${principal.principal_id}' is not authorized for requested tenant '${cleanRequested}'.`
    );
  }

  if (principalTenant) {
    return principalTenant;
  }

  if (isSystemAuthorized) {
    return '00000000-0000-0000-0000-000000000000';
  }

  throw new ScopeBoundaryViolationError(
    `NO AUTHORIZED TENANT CONTEXT: Authenticated principal '${principal.principal_id}' has no associated tenant context.`
  );
}
