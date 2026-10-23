import { createTestDb } from '../../packages/db/src/migrator.ts';
import { PgMemDbRepositories } from '../../packages/db/src/repositories.ts';
import type {
  DatabaseClient,
  DatabaseQueryResult,
  DatabasePrincipalContext,
  SecurityContextOptions,
  TenantContextTx,
  SystemContextTx,
  SystemTxContextInput,
} from '../../packages/db/src/types.ts';

/**
 * Pure unit test fake database client backed by pg-mem.
 * Strictly restricted to test suites under tests/ and src/__tests__/.
 */
export class FakeDatabaseClient implements DatabaseClient {
  private memDb: any;
  private client: any;
  private isClosed = false;

  constructor(options: { applyMigrations?: boolean; applySeed?: boolean } = { applyMigrations: true, applySeed: true }) {
    this.memDb = createTestDb(options);
    const pgMem = this.memDb.adapters.createPg();
    this.client = new pgMem.Client();
    this.client.connect().catch(() => {});
  }

  public async query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: unknown[]
  ): Promise<DatabaseQueryResult<R>> {
    if (this.isClosed) throw new Error('[FakeDatabaseClient] Client is closed');
    const res = await this.client.query(text, params);
    return {
      rows: res.rows || [],
      rowCount: res.rowCount ?? (res.rows ? res.rows.length : 0),
      command: res.command,
      oid: res.oid,
      fields: res.fields,
    };
  }

  public async withTenantTx<T>(
    principal: DatabasePrincipalContext,
    fn: (tx: TenantContextTx) => Promise<T>,
    _options: SecurityContextOptions = {}
  ): Promise<T> {
    if (this.isClosed) throw new Error('[FakeDatabaseClient] Client is closed');
    if (!principal || typeof principal !== 'object') {
      throw new Error('[SecurityBoundary] Denied: Invalid or missing principal context.');
    }

    const isAuthenticated = Boolean(principal.is_authenticated);
    const rawTenant = isAuthenticated ? (principal.tenant_id ?? principal.tenantId ?? null) : null;
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const validTenantId = (rawTenant && typeof rawTenant === 'string' && UUID_REGEX.test(rawTenant.trim()))
      ? rawTenant.trim()
      : null;

    const tenantSetting = validTenantId || '';
    const principalId = isAuthenticated
      ? (principal.principal_id ?? principal.principalId ?? 'anonymous').toString()
      : 'anonymous';
    const clearanceRank = isAuthenticated
      ? (principal.max_classification_rank ?? principal.maximumClassification ?? 0).toString()
      : '0';

    await this.client.query("SELECT set_config('app.tenant_id', $1, true);", [tenantSetting]).catch(() => {});
    await this.client.query("SELECT set_config('app.principal_id', $1, true);", [principalId]).catch(() => {});
    await this.client.query("SELECT set_config('app.clearance_rank', $1, true);", [clearanceRank]).catch(() => {});

    const tx: TenantContextTx = {
      query: (t: string, p?: unknown[]) => this.query(t, p),
      principal,
      tenantId: validTenantId,
      isSystem: false,
      client: this.client,
      repositories: new PgMemDbRepositories(this.client),
    };

    try {
      return await fn(tx);
    } finally {
      await this.client.query("SELECT set_config('app.tenant_id', '', false);").catch(() => {});
    }
  }

  public async withSystemTx<T>(
    context: SystemTxContextInput,
    fn: (tx: SystemContextTx) => Promise<T>,
    _options: SecurityContextOptions = {}
  ): Promise<T> {
    if (this.isClosed) throw new Error('[FakeDatabaseClient] Client is closed');
    const { actor, reason, principal } = context;

    if (!actor || typeof actor !== 'string' || actor.trim().length === 0) {
      throw new Error('[SecurityBoundary] Denied: withSystemTx requires an explicit actor.');
    }
    if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
      throw new Error('[SecurityBoundary] Denied: withSystemTx requires an explicit reason.');
    }

    const isServicePrincipal = Boolean(
      principal &&
      principal.is_authenticated &&
      (principal.is_service || principal.roles?.includes('service')) &&
      (
        principal.capabilities?.includes('system.db') ||
        principal.grants?.includes('system.db')
      )
    );

    if (!isServicePrincipal) {
      throw new Error('[SecurityBoundary] Denied: withSystemTx requires an authenticated service-account principal with the "system.db" capability.');
    }

    // Write audit row
    await this.client.query(
      `INSERT INTO security.platform_audit_log (
        principal_id, action, target_entity_type, target_entity_id, outcome, details
      ) VALUES ($1, 'SYSTEM_TX', 'DATABASE', 'SYSTEM', 'SUCCESS', jsonb_build_object('actor', $1::text, 'reason', $2::text));`,
      [actor, reason]
    ).catch(() => {});

    await this.client.query(
      `INSERT INTO security.system_tx_audit (actor, reason) VALUES ($1, $2);`,
      [actor, reason]
    ).catch(() => {});

    const tx: SystemContextTx = {
      query: (t: string, p?: unknown[]) => this.query(t, p),
      actor,
      reason,
      principal,
      isSystem: true,
      client: this.client,
      repositories: new PgMemDbRepositories(this.client),
    };

    return fn(tx);
  }

  public async healthCheck(): Promise<{ ok: boolean; latencyMs: number }> {
    return { ok: true, latencyMs: 1 };
  }

  public async close(): Promise<void> {
    this.isClosed = true;
    await this.client.end().catch(() => {});
  }
}

export function createFakeDatabaseClient(options?: { applyMigrations?: boolean; applySeed?: boolean }): FakeDatabaseClient {
  return new FakeDatabaseClient(options);
}
