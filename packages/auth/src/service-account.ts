/**
 * Service Account Registry and Authentication Service (R04 Task 3)
 * Manages service identities, credential hashes, allowed tenant boundaries, and capabilities.
 * INVARIANT: Service identity comes strictly from verified credentials and DB records, NEVER headers.
 */

import crypto from 'crypto';
import type { DatabaseClient } from '@caim/db';
import { ScopeBoundaryViolationError } from './types.ts';
import { safeCompareSecrets } from './jwt.ts';

export interface ServiceAccountRecord {
  id: string;
  name: string;
  allowed_tenants: string[];
  allowed_scopes: string[];
  credential_hash?: string | null;
  public_key?: string | null;
  status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  capabilities: string[];
  rotated_at?: string | null;
  created_at: string;
}

export class ServiceAccountRegistry {
  private static instance: ServiceAccountRegistry;
  private inMemoryAccounts = new Map<string, ServiceAccountRecord>();
  private dbClient?: DatabaseClient;

  constructor(dbClient?: DatabaseClient) {
    this.dbClient = dbClient;
  }

  public static getInstance(dbClient?: DatabaseClient): ServiceAccountRegistry {
    if (!ServiceAccountRegistry.instance) {
      ServiceAccountRegistry.instance = new ServiceAccountRegistry(dbClient);
    } else if (dbClient && !ServiceAccountRegistry.instance.dbClient) {
      ServiceAccountRegistry.instance.dbClient = dbClient;
    }
    return ServiceAccountRegistry.instance;
  }

  public setDbClient(dbClient: DatabaseClient): void {
    this.dbClient = dbClient;
  }

  /**
   * Registers or updates a service account in memory and/or database.
   */
  public async registerServiceAccount(account: Omit<ServiceAccountRecord, 'created_at'>): Promise<ServiceAccountRecord> {
    const record: ServiceAccountRecord = {
      ...account,
      created_at: new Date().toISOString(),
    };

    this.inMemoryAccounts.set(account.name, record);

    if (this.dbClient) {
      try {
        await this.dbClient.query(
          `INSERT INTO security.service_accounts (
             id, name, allowed_tenants, allowed_scopes, credential_hash, public_key, status, capabilities, rotated_at, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           ON CONFLICT (name) DO UPDATE SET
             allowed_tenants = EXCLUDED.allowed_tenants,
             allowed_scopes = EXCLUDED.allowed_scopes,
             credential_hash = EXCLUDED.credential_hash,
             public_key = EXCLUDED.public_key,
             status = EXCLUDED.status,
             capabilities = EXCLUDED.capabilities,
             rotated_at = EXCLUDED.rotated_at;`,
          [
            record.id,
            record.name,
            JSON.stringify(record.allowed_tenants),
            JSON.stringify(record.allowed_scopes),
            record.credential_hash || null,
            record.public_key || null,
            record.status,
            JSON.stringify(record.capabilities),
            record.rotated_at || null,
            record.created_at,
          ]
        );
      } catch {
        // Fall back to in-memory registration if table unavailable
      }
    }

    return record;
  }

  /**
   * Finds service account by name.
   */
  public async getServiceAccountByName(name: string): Promise<ServiceAccountRecord | undefined> {
    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          'SELECT * FROM security.service_accounts WHERE name = $1 LIMIT 1;',
          [name]
        );
        if (res && res.rows && res.rows.length > 0) {
          const row = res.rows[0];
          return {
            id: String(row.id),
            name: String(row.name),
            allowed_tenants: Array.isArray(row.allowed_tenants)
              ? row.allowed_tenants
              : typeof row.allowed_tenants === 'string'
              ? JSON.parse(row.allowed_tenants)
              : [],
            allowed_scopes: Array.isArray(row.allowed_scopes)
              ? row.allowed_scopes
              : typeof row.allowed_scopes === 'string'
              ? JSON.parse(row.allowed_scopes)
              : [],
            credential_hash: row.credential_hash ? String(row.credential_hash) : null,
            public_key: row.public_key ? String(row.public_key) : null,
            status: (row.status as any) || 'ACTIVE',
            capabilities: Array.isArray(row.capabilities)
              ? row.capabilities
              : typeof row.capabilities === 'string'
              ? JSON.parse(row.capabilities)
              : [],
            rotated_at: row.rotated_at ? String(row.rotated_at) : null,
            created_at: String(row.created_at),
          };
        }
      } catch {
        // Fall back to in-memory store
      }
    }

    return this.inMemoryAccounts.get(name);
  }

  /**
   * Authenticates a presented service token against registered service accounts.
   */
  public async authenticateServiceToken(
    token: string,
    configuredDiscoveryToken?: string,
    configuredServiceSecret?: string
  ): Promise<ServiceAccountRecord | undefined> {
    if (!token || typeof token !== 'string') return undefined;

    const presentedHash = crypto.createHash('sha256').update(token.trim()).digest('hex');

    // 1. Check in-memory registered service accounts first
    for (const sa of this.inMemoryAccounts.values()) {
      if (sa.status !== 'ACTIVE') continue;
      if (sa.credential_hash && safeCompareSecrets(presentedHash, sa.credential_hash)) {
        return sa;
      }
    }

    // 2. Check database security.service_accounts
    if (this.dbClient) {
      try {
        const res = await this.dbClient.query(
          "SELECT * FROM security.service_accounts WHERE status = 'ACTIVE';"
        );
        if (res && res.rows) {
          for (const row of res.rows) {
            if (row.credential_hash && safeCompareSecrets(presentedHash, String(row.credential_hash))) {
              return {
                id: String(row.id),
                name: String(row.name),
                allowed_tenants: Array.isArray(row.allowed_tenants)
                  ? row.allowed_tenants
                  : typeof row.allowed_tenants === 'string'
                  ? JSON.parse(row.allowed_tenants)
                  : [],
                allowed_scopes: Array.isArray(row.allowed_scopes)
                  ? row.allowed_scopes
                  : typeof row.allowed_scopes === 'string'
                  ? JSON.parse(row.allowed_scopes)
                  : [],
                credential_hash: row.credential_hash ? String(row.credential_hash) : null,
                public_key: row.public_key ? String(row.public_key) : null,
                status: (row.status as any) || 'ACTIVE',
                capabilities: Array.isArray(row.capabilities)
                  ? row.capabilities
                  : typeof row.capabilities === 'string'
                  ? JSON.parse(row.capabilities)
                  : [],
                rotated_at: row.rotated_at ? String(row.rotated_at) : null,
                created_at: String(row.created_at),
              };
            }
          }
        }
      } catch {
        // Continue
      }
    }

    // 3. Check environment-injected service tokens
    if (configuredDiscoveryToken && safeCompareSecrets(token, configuredDiscoveryToken)) {
      const existing = await this.getServiceAccountByName('service-discovery');
      if (existing) return existing;

      return {
        id: '00000000-0000-0000-0003-discovery001',
        name: 'service-discovery',
        allowed_tenants: [],
        allowed_scopes: ['discovery', 'reporting'],
        status: 'ACTIVE',
        capabilities: ['worker.manage'],
        created_at: new Date().toISOString(),
      };
    }

    if (configuredServiceSecret && safeCompareSecrets(token, configuredServiceSecret)) {
      const existing = await this.getServiceAccountByName('system_service');
      if (existing) return existing;

      return {
        id: '00000000-0000-0000-0003-systemserv01',
        name: 'system_service',
        allowed_tenants: ['*'],
        allowed_scopes: ['*'],
        status: 'ACTIVE',
        capabilities: ['worker.manage'],
        created_at: new Date().toISOString(),
      };
    }

    return undefined;
  }

  /**
   * Validates tenant scope boundary for a service account.
   */
  public validateTenantScope(serviceAccount: ServiceAccountRecord, requestedTenantId: string | null): string | null {
    if (!requestedTenantId || requestedTenantId.trim().length === 0) {
      return null;
    }

    const allowed = serviceAccount.allowed_tenants;
    if (!allowed || (!allowed.includes('*') && !allowed.includes(requestedTenantId))) {
      throw new ScopeBoundaryViolationError(
        `Service '${serviceAccount.name}' is not authorized to act on behalf of tenant '${requestedTenantId}'. Unauthorized tenant boundary violation rejected.`
      );
    }

    return requestedTenantId;
  }

  public clear(): void {
    this.inMemoryAccounts.clear();
  }
}

export const serviceAccountRegistry = ServiceAccountRegistry.getInstance();
