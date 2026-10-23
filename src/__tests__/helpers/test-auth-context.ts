import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank,
  CLASSIFICATION_CODE_TO_RANK,
  SecurityClassificationCode,
  createAnonymousPrincipal
} from '@caim/auth';
import { ApiRequestContext } from '@caim/api/router.ts';

/**
 * TEST-ONLY HELPER: Extracts principal identity from test headers for unit/contract tests.
 * This behavior has been strictly removed from production runtime code.
 * NEVER IMPORT OR USE THIS IN PRODUCTION CODE.
 */
export function extractTestPrincipalFromHeaders(headers: Record<string, string | string[] | undefined>): PrincipalContext {
  const authHeader = (headers['authorization'] || headers['Authorization']) as string | undefined;
  const principalIdHeader = (headers['x-principal-id'] || headers['X-Principal-Id']) as string | undefined;
  const rolesHeader = (headers['x-principal-roles'] || headers['X-Principal-Roles'] || headers['x-role'] || headers['X-Role']) as string | undefined;
  const tenantIdHeader = (headers['x-tenant-id'] || headers['X-Tenant-Id']) as string | undefined;
  const classificationHeader = (headers['x-max-classification'] || headers['X-Max-Classification']) as string | undefined;

  // Anonymous default when no simulated test identity provided
  if (!authHeader && !principalIdHeader && !rolesHeader) {
    return createAnonymousPrincipal();
  }

  let roles: BusinessRole[] = ['user'];
  if (rolesHeader) {
    roles = rolesHeader.split(',').map((r) => r.trim() as BusinessRole);
  } else if (authHeader?.includes('admin')) {
    roles = ['admin'];
  } else if (authHeader?.includes('analyst')) {
    roles = ['analyst'];
  } else if (authHeader?.includes('approver')) {
    roles = ['release_approver'];
  } else if (authHeader?.includes('auditor')) {
    roles = ['auditor'];
  } else if (authHeader?.includes('service')) {
    roles = ['operator'];
  }

  let maxRank = SecurityClassificationRank.INTERNAL;
  if (classificationHeader) {
    const code = classificationHeader.trim() as SecurityClassificationCode;
    if (code in CLASSIFICATION_CODE_TO_RANK) {
      maxRank = CLASSIFICATION_CODE_TO_RANK[code];
    }
  } else if (roles.includes('admin') || roles.includes('vault_reader')) {
    maxRank = SecurityClassificationRank.VAULT_RESTRICTED;
  } else if (roles.includes('analyst') || roles.includes('release_approver') || roles.includes('auditor')) {
    maxRank = SecurityClassificationRank.SENSITIVE;
  }

  const principalId = principalIdHeader || (authHeader ? `usr-${authHeader.replace('Bearer ', '').slice(0, 16)}` : `usr-${roles[0] || 'default'}`);
  const isService = principalId.startsWith('service-') || roles.includes('operator');

  return {
    principal_id: principalId,
    principalId,
    principalType: isService ? 'service' : 'user',
    is_authenticated: true,
    is_service: isService,
    service_name: isService ? 'system_service' : undefined,
    roles,
    tenant_id: tenantIdHeader || 'tenant-default',
    tenantId: tenantIdHeader || 'tenant-default',
    accessible_scope_ids: ['public', 'scope-default', tenantIdHeader || 'tenant-default'],
    max_classification_rank: maxRank,
    maximumClassification: maxRank,
    grants: roles.includes('admin') ? ['grant:all'] : ['grant:standard'],
    capabilities: roles.includes('admin') ? ['grant:all'] : ['grant:standard'],
    authenticationMethod: 'dev_bypass',
  };
}

/**
 * Creates an ApiRequestContext for test simulations, populating req.principal from test headers
 * or explicit principal override.
 */
export function createTestRequestContext(req: Partial<ApiRequestContext>): ApiRequestContext {
  const headers = req.headers || {};
  const principal = req.principal || extractTestPrincipalFromHeaders(headers);
  return {
    headers,
    params: req.params,
    query: req.query,
    body: req.body,
    requestId: req.requestId || (headers['x-request-id'] as string) || `req-test-${crypto.randomUUID()}`,
    url: req.url,
    method: req.method,
    principal,
  };
}
