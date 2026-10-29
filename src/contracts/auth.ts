/**
 * Authentication, Roles & Access Control Contracts
 * Engine: PF-05 (Authentication, Roles & Authorization Engine)
 * Architecture Version: 5.0.0 | Phase: P06
 */

export type UserRole = 'USER' | 'ADMIN' | 'RESEARCHER' | 'REVIEWER';

export type UserPermission =
  | 'READ_PUBLISHED_DNA'
  | 'READ_APPROVED_ARTISTS'
  | 'MANAGE_OWN_GENERATIONS'
  | 'MANAGE_OWN_FEEDBACK'
  | 'MUTATE_SOURCE_RECORDS'
  | 'MUTATE_EVIDENCE'
  | 'MUTATE_DATASETS'
  | 'MUTATE_METHODOLOGIES'
  | 'MUTATE_ARTIST_RESEARCH'
  | 'MUTATE_PUBLICATION_STATE'
  | 'MUTATE_PROMPT_VERSIONS'
  | 'READ_RESTRICTED_RAW_CONTENT'
  | 'OVERRIDE_GOVERNANCE'
  | 'READ_AUDIT_LOGS';

export interface AuthUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  role: UserRole;
  customClaims?: Record<string, unknown>;
  isAnonymous?: boolean;
  createdAt: string;
}

export const ROLE_PERMISSIONS_MATRIX: Record<UserRole, readonly UserPermission[]> = {
  USER: [
    'READ_PUBLISHED_DNA',
    'READ_APPROVED_ARTISTS',
    'MANAGE_OWN_GENERATIONS',
    'MANAGE_OWN_FEEDBACK',
  ],
  REVIEWER: [
    'READ_PUBLISHED_DNA',
    'READ_APPROVED_ARTISTS',
    'MANAGE_OWN_GENERATIONS',
    'MANAGE_OWN_FEEDBACK',
    'MUTATE_ARTIST_RESEARCH',
    'READ_RESTRICTED_RAW_CONTENT',
  ],
  RESEARCHER: [
    'READ_PUBLISHED_DNA',
    'READ_APPROVED_ARTISTS',
    'MANAGE_OWN_GENERATIONS',
    'MANAGE_OWN_FEEDBACK',
    'MUTATE_ARTIST_RESEARCH',
    'READ_RESTRICTED_RAW_CONTENT',
    'MUTATE_SOURCE_RECORDS',
    'MUTATE_EVIDENCE',
    'MUTATE_DATASETS',
  ],
  ADMIN: [
    'READ_PUBLISHED_DNA',
    'READ_APPROVED_ARTISTS',
    'MANAGE_OWN_GENERATIONS',
    'MANAGE_OWN_FEEDBACK',
    'MUTATE_ARTIST_RESEARCH',
    'READ_RESTRICTED_RAW_CONTENT',
    'MUTATE_SOURCE_RECORDS',
    'MUTATE_EVIDENCE',
    'MUTATE_DATASETS',
    'MUTATE_METHODOLOGIES',
    'MUTATE_PUBLICATION_STATE',
    'MUTATE_PROMPT_VERSIONS',
    'OVERRIDE_GOVERNANCE',
    'READ_AUDIT_LOGS',
  ],
};

export interface PrivilegedAuditEntry {
  id: string;
  actorId: string;
  actorRole: UserRole;
  action: string;
  resourceCollection: string;
  resourceId: string;
  beforeState: Record<string, unknown> | null;
  afterState: Record<string, unknown> | null;
  reason: string;
  clientIp?: string;
  timestamp: string;
}

export type AuthErrorCode =
  | 'UNAUTHENTICATED'
  | 'PERMISSION_DENIED'
  | 'ROLE_INSUFFICIENT'
  | 'RESOURCE_OWNERSHIP_VIOLATION'
  | 'RESTRICTED_CONTENT_VIOLATION'
  | 'PRIVILEGED_OVERRIDE_FAILED';

export class AuthorizationError extends Error {
  public readonly code: AuthErrorCode;
  public readonly errorCode: AuthErrorCode;
  public readonly requiredRole?: UserRole[];
  public readonly requiredPermission?: UserPermission;

  constructor(
    message: string,
    code: AuthErrorCode,
    details?: { requiredRole?: UserRole[]; requiredPermission?: UserPermission }
  ) {
    super(`[AuthorizationViolation: ${code}] ${message}`);
    this.name = 'AuthorizationError';
    this.code = code;
    this.errorCode = code;
    this.requiredRole = details?.requiredRole;
    this.requiredPermission = details?.requiredPermission;
  }
}
