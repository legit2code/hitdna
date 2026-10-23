import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank,
  createAnonymousPrincipal
} from '../../auth/src/index.ts';
import { UnauthorizedError, ForbiddenError } from './errors.ts';

export interface RequestAuthContext {
  principal: PrincipalContext;
  token?: string;
}

export class ApiAuthenticator {
  /**
   * Resolves authoritative principal context strictly from upstream verified request state.
   * NEVER extracts or trusts client-controlled identity headers in production.
   */
  public static resolveVerifiedPrincipal(principal?: PrincipalContext, requestId?: string): PrincipalContext {
    if (principal && principal.principal_id) {
      return principal;
    }
    return createAnonymousPrincipal(undefined, requestId);
  }

  /**
   * Enforce that the request is authenticated
   */
  public static requireAuthenticated(principal: PrincipalContext): void {
    if (!principal.is_authenticated || principal.roles.includes('anonymous')) {
      throw new UnauthorizedError('Authentication required. Missing or invalid authorization credentials.');
    }
  }

  /**
   * Enforce that the principal has at least one of the allowed roles
   */
  public static requireRoles(principal: PrincipalContext, allowedRoles: BusinessRole[]): void {
    this.requireAuthenticated(principal);
    if (principal.roles.includes('admin')) {
      return; // Admin bypasses standard role checks
    }
    const hasRole = principal.roles.some((r) => allowedRoles.includes(r));
    if (!hasRole) {
      throw new ForbiddenError(
        `Action requires one of the following roles: [${allowedRoles.join(', ')}]. Principal has: [${principal.roles.join(', ')}]`,
        { required_roles: allowedRoles, principal_roles: principal.roles }
      );
    }
  }

  /**
   * Enforce classification level clearance
   */
  public static requireClassification(principal: PrincipalContext, requiredClassification: SecurityClassificationRank): void {
    this.requireAuthenticated(principal);
    if (principal.max_classification_rank < requiredClassification) {
      throw new ForbiddenError('Insufficient security classification clearance for requested resource', {
        required_rank: requiredClassification,
        principal_rank: principal.max_classification_rank,
      });
    }
  }

  /**
   * Enforce tenant matching for multi-tenant isolation
   */
  public static requireTenant(principal: PrincipalContext, requiredTenantId: string): void {
    this.requireAuthenticated(principal);
    if (principal.roles.includes('admin')) {
      return;
    }
    if (principal.tenant_id !== requiredTenantId) {
      throw new ForbiddenError(`Access denied: principal tenant '${principal.tenant_id}' cannot access resource in tenant '${requiredTenantId}'`, {
        principal_tenant: principal.tenant_id,
        required_tenant: requiredTenantId,
      });
    }
  }

  /**
   * Enforce required capability or grant
   */
  public static requireCapability(principal: PrincipalContext, requiredCapability: string): void {
    this.requireAuthenticated(principal);
    if (principal.roles.includes('admin') || principal.grants.includes('grant:all')) {
      return;
    }
    const hasGrant = (principal.grants && principal.grants.includes(requiredCapability)) ||
                     (principal.capabilities && principal.capabilities.includes(requiredCapability));
    if (!hasGrant) {
      throw new ForbiddenError(`Action requires capability grant '${requiredCapability}'`, {
        required_capability: requiredCapability,
      });
    }
  }
}
