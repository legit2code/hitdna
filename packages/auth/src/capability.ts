/**
 * Restricted Capability Grants Management Service
 * Per-principal capability authorization (non-role-based)
 */

import crypto from 'crypto';
import type { DatabaseClient } from '@caim/db';

export interface RestrictedCapabilityGrant {
  grant_id: string;
  capability_key: string;
  principal_id: string;
  granted_by: string;
  justification: string;
  scope_limitations?: string[] | null;
  granted_at: string;
  revoked_at?: string | null;
}

export const SYSTEM_DB_CAPABILITY = 'system.db';
export type ComposerCapabilityKey = 'composer:full_access' | 'composer:restricted_access';
export type CoreCapabilityKey = typeof SYSTEM_DB_CAPABILITY | ComposerCapabilityKey;

export class AuthorizationStoreUnavailableError extends Error {
  constructor(message: string = 'Authoritative authorization store (PostgreSQL) is unavailable.') {
    super(`[CapabilityGrantService] ${message}`);
    this.name = 'AuthorizationStoreUnavailableError';
  }
}

export class CapabilityGrantService {
  private dbClient?: DatabaseClient;
  // Authoritative in-memory ledger for active grants (development and test only)
  private static inMemoryGrants: Map<string, RestrictedCapabilityGrant> = new Map();

  constructor(dbClient?: DatabaseClient) {
    this.dbClient = dbClient;
    this.ensureDefaultGrants();
  }

  public ensureDefaultGrants(): void {
    if (process.env.NODE_ENV === 'production') {
      return; // Never seed in-memory grants in production
    }
    const adminGrantId = '00000000-0000-0000-0002-000000000001';
    const adminPrincipalId = '00000000-0000-0000-0001-000000000001';
    const serverAdminPrincipalId = '00000000-0000-0000-0001-admin0000000';
    const serverAdminGrantId = '00000000-0000-0000-0002-admin0000000';

    if (!CapabilityGrantService.inMemoryGrants.has(adminGrantId)) {
      CapabilityGrantService.inMemoryGrants.set(adminGrantId, {
        grant_id: adminGrantId,
        capability_key: 'composer:full_access',
        principal_id: adminPrincipalId,
        granted_by: adminPrincipalId,
        justification: 'Platform owner — unrestricted composer access',
        scope_limitations: null,
        granted_at: new Date().toISOString(),
        revoked_at: null,
      });
    }

    const adminManageGrantId = '00000000-0000-0000-0002-000000000002';
    if (!CapabilityGrantService.inMemoryGrants.has(adminManageGrantId)) {
      CapabilityGrantService.inMemoryGrants.set(adminManageGrantId, {
        grant_id: adminManageGrantId,
        capability_key: 'admin:manage_principals',
        principal_id: adminPrincipalId,
        granted_by: adminPrincipalId,
        justification: 'Platform owner — principal and role administration',
        scope_limitations: null,
        granted_at: new Date().toISOString(),
        revoked_at: null,
      });
    }

    if (!CapabilityGrantService.inMemoryGrants.has(serverAdminGrantId)) {
      CapabilityGrantService.inMemoryGrants.set(serverAdminGrantId, {
        grant_id: serverAdminGrantId,
        capability_key: 'composer:full_access',
        principal_id: serverAdminPrincipalId,
        granted_by: serverAdminPrincipalId,
        justification: 'Platform admin (admin@caim.internal) — unrestricted composer access',
        scope_limitations: null,
        granted_at: new Date().toISOString(),
        revoked_at: null,
      });
    }

    const serverAdminManageGrantId = '00000000-0000-0000-0002-admin0000002';
    if (!CapabilityGrantService.inMemoryGrants.has(serverAdminManageGrantId)) {
      CapabilityGrantService.inMemoryGrants.set(serverAdminManageGrantId, {
        grant_id: serverAdminManageGrantId,
        capability_key: 'admin:manage_principals',
        principal_id: serverAdminPrincipalId,
        granted_by: serverAdminPrincipalId,
        justification: 'Platform admin (admin@caim.internal) — principal and role administration',
        scope_limitations: null,
        granted_at: new Date().toISOString(),
        revoked_at: null,
      });
    }
  }

  /**
   * Retrieves all grants (active and revoked)
   */
  public async listGrants(): Promise<RestrictedCapabilityGrant[]> {
    const isProduction = process.env.NODE_ENV === 'production';
    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          'SELECT * FROM security.restricted_capability_grants ORDER BY granted_at DESC;'
        );
        if (res && res.rows) {
          return res.rows.map((r: Record<string, unknown>) => ({
            grant_id: String(r.grant_id),
            capability_key: String(r.capability_key),
            principal_id: String(r.principal_id),
            granted_by: String(r.granted_by),
            justification: String(r.justification),
            scope_limitations: Array.isArray(r.scope_limitations) ? (r.scope_limitations as string[]) : (typeof r.scope_limitations === 'string' ? JSON.parse(r.scope_limitations) : null),
            granted_at: String(r.granted_at),
            revoked_at: r.revoked_at ? String(r.revoked_at) : null,
          }));
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (isProduction) {
          throw new AuthorizationStoreUnavailableError(`PostgreSQL query failed: ${errorMsg}`);
        }
        console.warn('[CapabilityGrantService] Database query failed; using in-memory grants in non-production environment');
      }
    } else if (isProduction) {
      throw new AuthorizationStoreUnavailableError('Database client is not configured in production mode.');
    }
    return Array.from(CapabilityGrantService.inMemoryGrants.values());
  }

  /**
   * Retrieves active non-revoked grants for a specific principal
   */
  public async getActiveGrantsForPrincipal(principalId: string): Promise<RestrictedCapabilityGrant[]> {
    const isProduction = process.env.NODE_ENV === 'production';
    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          `SELECT * FROM security.restricted_capability_grants 
           WHERE principal_id = $1 AND revoked_at IS NULL;`,
          [principalId]
        );
        if (res && res.rows) {
          return res.rows.map((r: Record<string, unknown>) => ({
            grant_id: String(r.grant_id),
            capability_key: String(r.capability_key),
            principal_id: String(r.principal_id),
            granted_by: String(r.granted_by),
            justification: String(r.justification),
            scope_limitations: Array.isArray(r.scope_limitations) ? (r.scope_limitations as string[]) : (typeof r.scope_limitations === 'string' ? JSON.parse(r.scope_limitations) : null),
            granted_at: String(r.granted_at),
            revoked_at: r.revoked_at ? String(r.revoked_at) : null,
          }));
        }
      } catch (err: unknown) {
        if (isProduction) {
          console.error('[CapabilityGrantService] FAIL_CLOSED: Database query failed for principal grants in production mode:', err);
          return []; // Fail closed: zero grants returned
        }
        console.warn('[CapabilityGrantService] Database query failed; using in-memory grants in non-production mode');
      }
    } else if (isProduction) {
      console.error('[CapabilityGrantService] FAIL_CLOSED: No database client configured in production mode.');
      return []; // Fail closed
    }

    return Array.from(CapabilityGrantService.inMemoryGrants.values()).filter(
      g => g.principal_id === principalId && !g.revoked_at
    );
  }

  /**
   * Checks whether principal holds an active (non-revoked) grant for capabilityKey
   */
  public async hasActiveGrant(principalId: string, capabilityKey: string): Promise<boolean> {
    const grants = await this.getActiveGrantsForPrincipal(principalId);
    return grants.some(g => g.capability_key === capabilityKey);
  }

  /**
   * Checks full Composer access including tier and technique category scope validation.
   */
  public async checkComposerAccess(
    principalId: string,
    techniqueCategory?: string
  ): Promise<{
    allowed: boolean;
    reason?: string;
    grant?: RestrictedCapabilityGrant;
    tier: 'full' | 'restricted' | 'none';
  }> {
    if (!principalId || principalId === 'anonymous') {
      return {
        allowed: false,
        reason: 'Authentication required: principal is anonymous or invalid.',
        tier: 'none',
      };
    }

    const activeGrants = await this.getActiveGrantsForPrincipal(principalId);

    // 1. Check for full access grant
    const fullGrant = activeGrants.find(g => g.capability_key === 'composer:full_access');
    if (fullGrant) {
      return {
        allowed: true,
        grant: fullGrant,
        tier: 'full',
      };
    }

    // 2. Check for restricted access grant
    const restrictedGrant = activeGrants.find(g => g.capability_key === 'composer:restricted_access');
    if (restrictedGrant) {
      if (!techniqueCategory) {
        // General access check passes for restricted tier
        return {
          allowed: true,
          grant: restrictedGrant,
          tier: 'restricted',
        };
      }

      // Check technique category scope limitations
      const allowedCategories = restrictedGrant.scope_limitations;
      if (!allowedCategories || allowedCategories.length === 0 || allowedCategories.includes('*')) {
        return {
          allowed: true,
          grant: restrictedGrant,
          tier: 'restricted',
        };
      }

      const normalizedRequested = techniqueCategory.trim().toUpperCase();
      const isAllowed = allowedCategories.some(c => c.trim().toUpperCase() === normalizedRequested);

      if (isAllowed) {
        return {
          allowed: true,
          grant: restrictedGrant,
          tier: 'restricted',
        };
      }

      return {
        allowed: false,
        reason: `Technique category '${techniqueCategory}' is not authorized for restricted capability grant (Allowed: ${allowedCategories.join(', ')})`,
        grant: restrictedGrant,
        tier: 'restricted',
      };
    }

    return {
      allowed: false,
      reason: `Principal '${principalId}' does not have an active capability grant for Composer ('composer:full_access' or 'composer:restricted_access'). Admin role alone does not confer composer access.`,
      tier: 'none',
    };
  }

  /**
   * Creates and stores a new capability grant
   */
  public async grantCapability(params: {
    capability_key: string;
    principal_id: string;
    granted_by: string;
    justification: string;
    scope_limitations?: string[] | null;
  }): Promise<RestrictedCapabilityGrant> {
    const grant_id = crypto.randomUUID();
    const granted_at = new Date().toISOString();

    const record: RestrictedCapabilityGrant = {
      grant_id,
      capability_key: params.capability_key,
      principal_id: params.principal_id,
      granted_by: params.granted_by,
      justification: params.justification,
      scope_limitations: params.scope_limitations || null,
      granted_at,
      revoked_at: null,
    };

    const isProduction = process.env.NODE_ENV === 'production';
    if (isProduction && !this.dbClient) {
      throw new AuthorizationStoreUnavailableError('Cannot grant capability: Database client is not configured in production mode.');
    }

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `INSERT INTO security.restricted_capability_grants 
           (grant_id, capability_key, principal_id, granted_by, justification, scope_limitations, granted_at, revoked_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`,
          [
            record.grant_id,
            record.capability_key,
            record.principal_id,
            record.granted_by,
            record.justification,
            record.scope_limitations ? JSON.stringify(record.scope_limitations) : null,
            record.granted_at,
            null,
          ]
        );
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (isProduction) {
          throw new AuthorizationStoreUnavailableError(`Failed to persist capability grant in PostgreSQL: ${errorMsg}`);
        }
      }
    }

    CapabilityGrantService.inMemoryGrants.set(grant_id, record);
    return record;
  }

  /**
   * Revokes an existing capability grant
   */
  public async revokeCapability(params: {
    grant_id: string;
    revoked_by: string;
  }): Promise<RestrictedCapabilityGrant> {
    const isProduction = process.env.NODE_ENV === 'production';
    if (isProduction && !this.dbClient) {
      throw new AuthorizationStoreUnavailableError('Cannot revoke capability: Database client is not configured in production mode.');
    }

    const revoked_at = new Date().toISOString();

    let record = CapabilityGrantService.inMemoryGrants.get(params.grant_id);
    if (record) {
      record.revoked_at = revoked_at;
    }

    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          `UPDATE security.restricted_capability_grants 
           SET revoked_at = $1 
           WHERE grant_id = $2 
           RETURNING *;`,
          [revoked_at, params.grant_id]
        );
        if (res && res.rows && res.rows.length > 0) {
          const r: Record<string, unknown> = res.rows[0];
          record = {
            grant_id: String(r.grant_id),
            capability_key: String(r.capability_key),
            principal_id: String(r.principal_id),
            granted_by: String(r.granted_by),
            justification: String(r.justification),
            scope_limitations: Array.isArray(r.scope_limitations) ? (r.scope_limitations as string[]) : (typeof r.scope_limitations === 'string' ? JSON.parse(r.scope_limitations) : null),
            granted_at: String(r.granted_at),
            revoked_at: r.revoked_at ? String(r.revoked_at) : null,
          };
          CapabilityGrantService.inMemoryGrants.set(params.grant_id, record);
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (isProduction) {
          throw new AuthorizationStoreUnavailableError(`Failed to revoke capability grant in PostgreSQL: ${errorMsg}`);
        }
      }
    }

    if (!record) {
      throw new Error(`Capability grant '${params.grant_id}' not found.`);
    }

    return record;
  }
}
