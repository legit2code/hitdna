import { createTestDb } from "@caim/db/migrator.ts";
import { PostgresDatabaseAdapter } from "@caim/db/postgres-adapter.ts";
import type { DatabaseClient } from "@caim/db/types.ts";
import { ServerConfig } from "@caim/config";

export interface DatabaseInfrastructure {
  dbClient: DatabaseClient;
  dbAdapter: PostgresDatabaseAdapter | null;
}

export async function initDatabase(config: ServerConfig): Promise<DatabaseInfrastructure> {
  const isProduction = process.env.NODE_ENV === "production" || config.env === "production";
  const databaseUrl = process.env.DATABASE_URL || process.env.SUPABASE_DB_URL || process.env.POSTGRES_URL;

  let dbClient: DatabaseClient | null = null;
  let dbAdapter: PostgresDatabaseAdapter | null = null;

  if (isProduction) {
    // FAIL CLOSED: If in production and no real DATABASE_URL is configured, refuse to start!
    if (!databaseUrl || databaseUrl.trim().length === 0) {
      const fatalMessage =
        '[FATAL PRODUCTION ERROR] Server startup failed closed: NODE_ENV is set to "production" but no DATABASE_URL (or SUPABASE_DB_URL / POSTGRES_URL) is configured. In-memory database (pg-mem) fallback is strictly prohibited in production mode. Please configure a valid PostgreSQL connection string in DATABASE_URL.';
      console.error(fatalMessage);
      throw new Error(fatalMessage);
    }

    console.log("[CAIM Database] Initializing production PostgreSQL connection pool (pg.Pool)...");
    dbAdapter = new PostgresDatabaseAdapter({
      connectionString: databaseUrl,
      applicationName: "caim-control-plane-prod",
    });

    const health = await dbAdapter.healthCheck();
    if (!health.ok) {
      const connErr = `[FATAL PRODUCTION ERROR] Production database connection failed: ${health.error}`;
      console.error(connErr);
      throw new Error(connErr);
    }
    console.log(
      `[CAIM Database] Production PostgreSQL connected successfully (Latency: ${health.latencyMs}ms, Version: ${health.version || "unknown"})`
    );

    // In production, verify schema version and table existence. Fail startup if required migrations have not been applied.
    // Production API startup must not run DDL.
    try {
      const schemaCheck = await dbAdapter.verifySchema();
      if (!schemaCheck.verified) {
        const fatalErr = `[FATAL PRODUCTION ERROR] Database migration execution failed: ${schemaCheck.error || "Schema not up to date"}. Startup terminated — application must not run against a broken or out-of-date schema.`;
        console.error(fatalErr);
        throw new Error(fatalErr);
      }
      console.log(
        `[CAIM Database] PostgreSQL schema verified. All ${schemaCheck.appliedMigrations.length} migrations and required tables are intact.`
      );
    } catch (migErr: any) {
      const fatalErr = `[FATAL PRODUCTION ERROR] Database migration execution failed: ${migErr.message}. Startup terminated — application must not run against a broken or out-of-date schema.`;
      console.error(fatalErr);
      throw new Error(fatalErr);
    }

    dbClient = dbAdapter;
  } else {
    // Dev / Test configuration:
    // Dev falls back to Docker Postgres, attempting real PostgreSQL service first (R05 Task 8)
    const devDbCandidates = [
      databaseUrl,
      process.env.DOCKER_POSTGRES_URL,
      process.env.CI_DATABASE_URL,
      process.env.DEV_DATABASE_URL,
      process.env.LOCAL_POSTGRES_URL,
    ].filter(Boolean) as string[];

    for (const candUrl of devDbCandidates) {
      try {
        const candidateAdapter = new PostgresDatabaseAdapter({
          connectionString: candUrl,
          applicationName: "caim-control-plane-dev",
          connectionTimeoutMillis: 400,
        });
        const health = await candidateAdapter.healthCheck();
        if (health.ok) {
          console.log(`[CAIM Database] PostgreSQL connected via ${candUrl.replace(/:[^:@]+@/, ':***@')} (Latency: ${health.latencyMs}ms)`);
          dbAdapter = candidateAdapter;
          await dbAdapter.runMigrations({ applySeed: true }).catch((e) => {
            console.warn(`[CAIM Database] Dev migration notice: ${e.message}`);
          });
          dbClient = dbAdapter;
          break;
        }
      } catch {
        // Try next candidate
      }
    }

    // Ephemeral unit test fallback strictly restricted to non-production environments
    if (!dbClient) {
      console.warn(
        "[CAIM Database] Development notice: Initializing local in-memory fallback. Production and CI strictly require PostgreSQL."
      );
      const memDb = createTestDb({ applyMigrations: true, applySeed: true });
      try {
        const tcpServer = await (memDb as any).adapters.bindServer();
        dbAdapter = new PostgresDatabaseAdapter({
          connectionString: tcpServer.postgresConnectionString,
          applicationName: "caim-control-plane-dev",
          poolConfig: { max: 5 },
        });
        dbClient = dbAdapter;
      } catch (bindErr: any) {
        console.warn(`[CAIM Database] bindServer fallback to pgMem client: ${bindErr.message}`);
        const pgMem = memDb.adapters.createPg();
        const memClient = new pgMem.Client();
        await memClient.connect();
        dbClient = memClient as any;
      }
    }
  }

  return { dbClient: dbClient!, dbAdapter };
}
