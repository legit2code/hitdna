/**
 * Architecture V2.0.1 Document 13 & 21 Types: Authentication, Roles, RLS & Vault Boundaries
 */

export type BusinessRole = 
  | 'anonymous'
  | 'user'
  | 'analyst'
  | 'vault_reader'
  | 'reviewer'
  | 'release_approver'
  | 'auditor'
  | 'operator'
  | 'admin'
  | 'system_admin'
  | 'security_officer';

export type ServiceIdentity = 
  | 'service-analysis'
  | 'service-knowledge'
  | 'service-lifecycle'
  | 'service-decision'
  | 'service-discovery'
  | 'system_service';

export type SecurityClassificationCode = 
  | 'PUBLIC_METADATA'
  | 'INTERNAL'
  | 'SENSITIVE'
  | 'VAULT_RESTRICTED';

export enum SecurityClassificationRank {
  PUBLIC_METADATA = 0,
  INTERNAL = 1,
  SENSITIVE = 2,
  VAULT_RESTRICTED = 3,
}

export const CLASSIFICATION_CODE_TO_RANK: Record<SecurityClassificationCode, SecurityClassificationRank> = {
  PUBLIC_METADATA: SecurityClassificationRank.PUBLIC_METADATA,
  INTERNAL: SecurityClassificationRank.INTERNAL,
  SENSITIVE: SecurityClassificationRank.SENSITIVE,
  VAULT_RESTRICTED: SecurityClassificationRank.VAULT_RESTRICTED,
};

export const CLASSIFICATION_RANK_TO_CODE: Record<SecurityClassificationRank, SecurityClassificationCode> = {
  [SecurityClassificationRank.PUBLIC_METADATA]: 'PUBLIC_METADATA',
  [SecurityClassificationRank.INTERNAL]: 'INTERNAL',
  [SecurityClassificationRank.SENSITIVE]: 'SENSITIVE',
  [SecurityClassificationRank.VAULT_RESTRICTED]: 'VAULT_RESTRICTED',
};

export interface AccessScope {
  scope_id: string;
  scope_type: 'PLATFORM' | 'ORGANIZATION';
  tenant_id?: string | null;
}

export interface AccessGrant {
  grant_id: string;
  principal_id: string;
  grant_type: string;
  target_scope_id?: string | null;
  expires_at?: string | null;
}

export type AuthenticationMethod = 
  | 'bearer_jwt' 
  | 'service_secret' 
  | 'service_token' 
  | 'dev_bypass' 
  | 'anonymous';

export interface PrincipalContext {
  // Authoritative identity identifiers (both snake_case and camelCase supported for compatibility)
  principal_id: string;
  principalId?: string;
  principalType?: 'user' | 'service' | 'anonymous';
  is_authenticated: boolean;
  is_service: boolean;
  service_name?: ServiceIdentity;

  // Authoritative role and authorization state
  roles: BusinessRole[];
  tenant_id: string | null;
  tenantId?: string | null;
  accessible_scope_ids: string[];
  tenant_memberships?: Array<{ tenant_id: string; status?: string }>;
  max_classification_rank: SecurityClassificationRank;
  maximumClassification?: SecurityClassificationRank;
  grants: string[];
  capabilities?: string[];

  // Authentication metadata established only by trusted verification
  authenticationMethod?: AuthenticationMethod;
  credentialId?: string;
  tokenIssuer?: string;
  tokenAudience?: string;
  tokenExpiresAt?: number;
  correlation_id?: string;
  requestId?: string;

  // Audit and override tracking
  is_override_active?: boolean;
  override_justification?: string;
}

export interface AuditedOverrideRequest {
  actor_id: string;
  action: string;
  target_resource_id: string;
  target_resource_type: string;
  justification: string;
  correlation_id: string;
  metadata?: Record<string, any>;
}

export class UnauthorizedAccessError extends Error {
  constructor(message: string, public details?: Record<string, any>) {
    super(message);
    this.name = 'UnauthorizedAccessError';
  }
}

export class UnauthorizedVaultAccessError extends UnauthorizedAccessError {
  constructor(message: string = 'Unauthorized retrieval of VAULT_RESTRICTED data', details?: Record<string, any>) {
    super(message, details);
    this.name = 'UnauthorizedVaultAccessError';
  }
}

export class ScopeBoundaryViolationError extends UnauthorizedAccessError {
  constructor(message: string = 'Cross-tenant or unauthorized scope access violation', details?: Record<string, any>) {
    super(message, details);
    this.name = 'ScopeBoundaryViolationError';
  }
}
