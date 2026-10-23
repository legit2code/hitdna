import { describe, it, expect } from 'vitest';
import { 
  PostgresDatabaseAdapter, 
  createProductionDb, 
  resolveDatabaseUrl,
  createTestDb 
} from '@caim/db';

describe('Production Database Adapter & Fail-Closed Enforcement', () => {
  it('should fail fast if connectionString / DATABASE_URL is not provided to createProductionDb', () => {
    const originalUrl = process.env.DATABASE_URL;
    const originalSupabase = process.env.SUPABASE_DB_URL;
    const originalPostgres = process.env.POSTGRES_URL;

    try {
      delete process.env.DATABASE_URL;
      delete process.env.SUPABASE_DB_URL;
      delete process.env.POSTGRES_URL;

      expect(() => createProductionDb()).toThrowError(/Missing database connection string/);
    } finally {
      if (originalUrl) process.env.DATABASE_URL = originalUrl;
      if (originalSupabase) process.env.SUPABASE_DB_URL = originalSupabase;
      if (originalPostgres) process.env.POSTGRES_URL = originalPostgres;
    }
  });

  it('should strictly throw a fatal security violation if createTestDb is called in production mode', () => {
    const originalEnv = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      expect(() => createTestDb()).toThrowError(/createTestDb\(\) is strictly restricted to test and development environments/);
    } finally {
      process.env.NODE_ENV = originalEnv;
    }
  });

  it('should connect to PostgreSQL via PostgresDatabaseAdapter, execute queries, and perform health checks', async () => {
    // Spin up an in-memory TCP server representing PostgreSQL
    const devDb = createTestDb({ applyMigrations: true });
    const tcpServer = await (devDb as any).adapters.bindServer();
    const connectionString = tcpServer.postgresConnectionString;

    const adapter = new PostgresDatabaseAdapter({
      connectionString,
      applicationName: 'test-adapter-runner',
    });

    try {
      // 1. Health check
      const health = await adapter.healthCheck();
      expect(health.ok).toBe(true);
      expect(health.latencyMs).toBeGreaterThanOrEqual(0);
      expect(health.currentDatabase).toBe('postgres');

      // 2. Direct query execution
      const queryRes = await adapter.query('SELECT 42 AS answer, NOW() AS ts;');
      expect(queryRes.rows[0].answer).toBe(42);

      // 3. Migration tracking execution
      const migResult = await adapter.runMigrations();
      expect(migResult).toBeDefined();
      expect(Array.isArray(migResult.applied)).toBe(true);
      expect(Array.isArray(migResult.skipped)).toBe(true);

      // 4. Schema migrations table was populated
      const schemaMigrations = await adapter.query('SELECT count(*)::int as count FROM public.schema_migrations;');
      expect(schemaMigrations.rows[0].count).toBeGreaterThan(0);
    } finally {
      await adapter.close();
      await tcpServer.close();
    }
  }, 20000);
});
