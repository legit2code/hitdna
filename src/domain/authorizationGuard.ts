/**
 * Server-Side Authorization Guard & Privileged Audit Engine
 * Engine: PF-05 (Authentication, Roles & Authorization Engine)
 * Architecture Version: 5.0.0 | Phase: P06
 */

import {
  AuthUser,
  UserRole,
  UserPermission,
  ROLE_PERMISSIONS_MATRIX,
  AuthorizationError,
  PrivilegedAuditEntry,
} from '../contracts/auth.js';

export class AuthorizationGuard {
  private privilegedAudits: PrivilegedAuditEntry[] = [];

  /**
   * Checks if user has a specific permission based on their role.
   */
  public hasPermission(user: AuthUser | null | undefined, permission: UserPermission): boolean {
    if (!user) return false;
    const permissions = ROLE_PERMISSIONS_MATRIX[user.role] || [];
    return permissions.includes(permission);
  }

  /**
   * Asserts user has permission; throws AuthorizationError if not.
   */
  public assertPermission(
    user: AuthUser | null | undefined,
    permission: UserPermission,
    context?: string
  ): void {
    if (!user) {
      throw new AuthorizationError(
        `Authentication required to perform ${context || permission}`,
        'UNAUTHENTICATED',
        { requiredPermission: permission }
      );
    }

    if (!this.hasPermission(user, permission)) {
      throw new AuthorizationError(
        `User ${user.uid} with role ${user.role} lacks required permission ${permission} for ${context || 'operation'}`,
        'PERMISSION_DENIED',
        { requiredPermission: permission }
      );
    }
  }

  /**
   * Asserts user has one of the allowed roles.
   */
  public assertRole(
    user: AuthUser | null | undefined,
    allowedRoles: UserRole[],
    context?: string
  ): void {
    if (!user) {
      throw new AuthorizationError(
        `Authentication required for ${context || 'operation'}`,
        'UNAUTHENTICATED',
        { requiredRole: allowedRoles }
      );
    }

    if (!allowedRoles.includes(user.role)) {
      throw new AuthorizationError(
        `User ${user.uid} with role ${user.role} is not authorized for ${context || 'operation'}. Required roles: [${allowedRoles.join(', ')}]`,
        'ROLE_INSUFFICIENT',
        { requiredRole: allowedRoles }
      );
    }
  }

  /**
   * Asserts that a user owns the resource, or has ADMIN privileges.
   */
  public assertResourceOwnership(
    user: AuthUser | null | undefined,
    resourceOwnerId: string,
    context?: string
  ): void {
    if (!user) {
      throw new AuthorizationError(
        `Authentication required to access resource: ${context || 'unknown'}`,
        'UNAUTHENTICATED'
      );
    }

    // ADMINs can bypass ownership checks for operational moderation/recovery
    if (user.role === 'ADMIN') {
      return;
    }

    if (user.uid !== resourceOwnerId) {
      throw new AuthorizationError(
        `User ${user.uid} cannot access resource owned by ${resourceOwnerId} (${context || 'resource'})`,
        'RESOURCE_OWNERSHIP_VIOLATION'
      );
    }
  }

  /**
   * Comprehensive resource mutation guard enforcing P06 rules:
   * 1. Published DNA & approved profiles read is open, but mutation requires ADMIN or RESEARCHER.
   * 2. Source records, evidence, datasets, methodologies require RESEARCHER/ADMIN.
   * 3. Prompt versions, publication state, and methodologies require ADMIN.
   * 4. Generation requests/results/feedback can only be managed by owner or ADMIN.
   * 5. Raw provider content cannot be read by normal USERs.
   */
  public assertResourceMutation(
    user: AuthUser | null | undefined,
    options: {
      resourceCollection: string;
      action: 'CREATE' | 'UPDATE' | 'DELETE';
      resourceOwnerId?: string;
      isPublished?: boolean;
      context?: string;
    }
  ): void {
    const { resourceCollection, action, resourceOwnerId, isPublished, context } = options;

    if (!user) {
      throw new AuthorizationError(
        `Unauthenticated mutation attempted on ${resourceCollection}`,
        'UNAUTHENTICATED'
      );
    }

    switch (resourceCollection) {
      case 'publishedHitDnaSnapshots':
      case 'publicationState':
      case 'methodologies':
      case 'promptTemplates':
        // Only ADMIN may mutate publication state, methodologies, and prompt versions
        this.assertRole(user, ['ADMIN'], `${action} on ${resourceCollection}`);
        break;

      case 'sourceRecords':
      case 'sourceObservations':
      case 'researchRuns':
      case 'evaluationRuns':
      case 'artistStyleProfiles':
      case 'artistProfileEvidence':
        // Only RESEARCHER or ADMIN may mutate research facts and source records
        this.assertRole(user, ['RESEARCHER', 'ADMIN'], `${action} on ${resourceCollection}`);
        break;

      case 'rawProviderPayloads':
        // Raw provider content mutations strictly restricted
        this.assertRole(user, ['ADMIN'], `${action} on ${resourceCollection}`);
        break;

      case 'generationRequests':
      case 'songSpecifications':
      case 'lyricsResults':
      case 'soundPromptResults':
      case 'generationRecords':
      case 'generationFeedback':
        // Normal users can only manage their own records
        if (resourceOwnerId) {
          this.assertResourceOwnership(user, resourceOwnerId, `${action} on ${resourceCollection}`);
        }
        break;

      case 'auditEvents':
      case 'privilegedAudits':
        this.assertRole(user, ['ADMIN'], `${action} on audit logs`);
        break;

      default:
        // Default to requiring ADMIN for unknown collections
        this.assertRole(user, ['ADMIN'], `${action} on unrecognized collection ${resourceCollection}`);
        break;
    }
  }

  /**
   * Enforces raw/restricted provider content access:
   * Normal users cannot access raw third-party payloads under licensing policy.
   */
  public assertRawContentAccess(user: AuthUser | null | undefined, providerId: string): void {
    if (!user) {
      throw new AuthorizationError(
        `Authentication required to view raw content from provider ${providerId}`,
        'UNAUTHENTICATED'
      );
    }

    if (user.role !== 'ADMIN' && user.role !== 'RESEARCHER') {
      throw new AuthorizationError(
        `Role ${user.role} is prohibited from reading raw provider content from ${providerId}. Requires RESEARCHER or ADMIN.`,
        'RESTRICTED_CONTENT_VIOLATION'
      );
    }
  }

  /**
   * Logs a privileged mutation or override to the audit trail.
   */
  public recordPrivilegedAudit(
    actor: AuthUser,
    action: string,
    resourceCollection: string,
    resourceId: string,
    reason: string,
    beforeState: Record<string, unknown> | null = null,
    afterState: Record<string, unknown> | null = null,
    clientIp?: string
  ): PrivilegedAuditEntry {
    if (actor.role !== 'ADMIN') {
      throw new AuthorizationError(
        `Only ADMIN role may record or execute privileged overrides. Actor ${actor.uid} has role ${actor.role}`,
        'ROLE_INSUFFICIENT'
      );
    }

    const entry: PrivilegedAuditEntry = {
      id: `pvd_audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      actorId: actor.uid,
      actorRole: actor.role,
      action,
      resourceCollection,
      resourceId,
      beforeState,
      afterState,
      reason,
      clientIp,
      timestamp: new Date().toISOString(),
    };

    this.privilegedAudits.push(entry);
    return entry;
  }

  /**
   * Retrieves privileged audit entries (restricted to ADMIN).
   */
  public getPrivilegedAudits(requestingUser: AuthUser): PrivilegedAuditEntry[] {
    this.assertRole(requestingUser, ['ADMIN'], 'getPrivilegedAudits');
    return [...this.privilegedAudits];
  }

  /**
   * Clears in-memory audits (for test harnesses).
   */
  public resetForTesting(): void {
    this.privilegedAudits = [];
  }
}

export const defaultAuthGuard = new AuthorizationGuard();
