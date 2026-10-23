import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank, 
  ServiceIdentity,
  AuthenticationMethod
} from './types.ts';

export interface ResolveClaimsInput {
  principal_id?: string;
  is_service?: boolean;
  service_name?: ServiceIdentity;
  roles?: BusinessRole[];
  tenant_id?: string | null;
  accessible_scope_ids?: string[];
  grants?: string[];
  capabilities?: string[];
  authentication_method?: AuthenticationMethod;
  credential_id?: string;
  token_issuer?: string;
  token_audience?: string;
  token_expires_at?: number;
  correlation_id?: string;
  request_id?: string;
}

/**
 * Scoped service role matrix — no implicit superuser/admin access
 */
export const SERVICE_DEFAULT_ROLES: Record<string, BusinessRole[]> = {
  'service-discovery': ['operator'],
  'service-analysis': ['admin', 'operator'],
  'service-knowledge': ['admin', 'operator'],
  'service-lifecycle': ['operator'],
  'service-decision': ['operator', 'analyst'],
  'system_service': ['operator'],
};

/**
 * Canonical anonymous principal context — fail-closed baseline
 */
export function createAnonymousPrincipal(correlationId?: string, requestId?: string): PrincipalContext {
  return {
    principal_id: 'anonymous',
    principalId: 'anonymous',
    principalType: 'anonymous',
    is_authenticated: false,
    is_service: false,
    roles: ['anonymous'],
    tenant_id: null,
    tenantId: null,
    accessible_scope_ids: ['00000000-0000-0000-0000-000000000001'], // Platform public scope
    max_classification_rank: SecurityClassificationRank.PUBLIC_METADATA,
    maximumClassification: SecurityClassificationRank.PUBLIC_METADATA,
    grants: [],
    capabilities: [],
    authenticationMethod: 'anonymous',
    correlation_id: correlationId,
    requestId: requestId,
  };
}

/**
 * Resolves maximum authorized security classification clearance for a principal based on their roles and grants.
 */
export function resolveClassificationClearance(roles: BusinessRole[], grants: string[] = []): SecurityClassificationRank {
  if (roles.includes('admin') || roles.includes('vault_reader') || grants.includes('vault_reader')) {
    return SecurityClassificationRank.VAULT_RESTRICTED;
  }
  if (roles.includes('reviewer') || roles.includes('release_approver') || roles.includes('analyst') || roles.includes('auditor') || roles.includes('operator')) {
    return SecurityClassificationRank.SENSITIVE;
  }
  if (roles.includes('user')) {
    return SecurityClassificationRank.INTERNAL;
  }
  return SecurityClassificationRank.PUBLIC_METADATA;
}

/**
 * Resolves full PrincipalContext from input identity claims and memberships.
 */
export function resolvePrincipalClaims(input: ResolveClaimsInput): PrincipalContext {
  const isService = Boolean(input.is_service || input.service_name);
  const rawRoles = input.roles || [];
  
  // Anonymous fallback
  if (!input.principal_id && !isService) {
    return createAnonymousPrincipal(input.correlation_id, input.request_id);
  }

  // Determine effective roles: services receive scoped roles, never implicit admin superuser
  const effectiveRoles: BusinessRole[] = isService 
    ? (rawRoles.length > 0 ? rawRoles : (input.service_name && SERVICE_DEFAULT_ROLES[input.service_name] ? [...SERVICE_DEFAULT_ROLES[input.service_name]] : ['operator']))
    : (rawRoles.length > 0 ? rawRoles : ['user']);

  const grants = input.grants || [];
  const capabilities = input.capabilities || [...grants];
  const maxClearance = resolveClassificationClearance(effectiveRoles, grants);
  const principalId = input.principal_id || (input.service_name ? `service:${input.service_name}` : 'unknown');
  const tenantId = input.tenant_id ?? null;

  return {
    principal_id: principalId,
    principalId: principalId,
    principalType: isService ? 'service' : 'user',
    is_authenticated: true,
    is_service: isService,
    service_name: input.service_name,
    roles: effectiveRoles,
    tenant_id: tenantId,
    tenantId: tenantId,
    accessible_scope_ids: input.accessible_scope_ids || ['00000000-0000-0000-0000-000000000001'],
    max_classification_rank: maxClearance,
    maximumClassification: maxClearance,
    grants,
    capabilities,
    authenticationMethod: input.authentication_method || (isService ? 'service_secret' : 'bearer_jwt'),
    credentialId: input.credential_id,
    tokenIssuer: input.token_issuer,
    tokenAudience: input.token_audience,
    tokenExpiresAt: input.token_expires_at,
    correlation_id: input.correlation_id,
    requestId: input.request_id || input.correlation_id,
  };
}
