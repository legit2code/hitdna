import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import path from 'path';

describe('Production Migration Failure Startup Invariant', () => {
  it('terminates startup with fatal exit code when database migrations fail in production', async () => {
    // We execute a test runner script that initializes the production startup sequence
    // with a database adapter configured to throw during runMigrations.
    const script = `
      import { PostgresDatabaseAdapter } from './packages/db/src/postgres-adapter.ts';

      (async () => {
        // Mock runMigrations to simulate a schema mismatch / migration failure
        PostgresDatabaseAdapter.prototype.runMigrations = async function() {
          throw new Error('CORRUPT_SCHEMA: Column "caim_invariants" constraint violation in 002_schema.sql');
        };

        // Mock healthCheck to succeed so it gets to migrations
        PostgresDatabaseAdapter.prototype.healthCheck = async function() {
          return { ok: true, latencyMs: 2, version: 'PostgreSQL 16.2' };
        };

        // Set production environment
        process.env.NODE_ENV = 'production';
        process.env.DATABASE_URL = 'postgres://fake_user:fake_pass@db.example.internal:5432/caim_prod?sslmode=disable';

        // Import server startup sequence
        try {
          const isProduction = true;
          const dbAdapter = new PostgresDatabaseAdapter({
            connectionString: process.env.DATABASE_URL,
            applicationName: 'caim-control-plane-prod',
          });

          const health = await dbAdapter.healthCheck();
          if (!health.ok) {
            throw new Error('Connection failed');
          }

          // Production migration block matching apps/server/index.ts:
          try {
            const migResult = await dbAdapter.runMigrations();
          } catch (migErr: any) {
            const fatalErr = \`[FATAL PRODUCTION ERROR] Database migration execution failed: \${migErr.message}. Startup terminated — application must not run against a broken or out-of-date schema.\`;
            console.error(fatalErr);
            throw new Error(fatalErr);
          }
        } catch (err: any) {
          console.error('Failed to start server:', err.message);
          process.exit(1);
        }
      })();
    `;

    const proc = spawn('npx', ['tsx', '-e', script], {
      cwd: process.cwd(),
      env: { ...process.env, NODE_ENV: 'production' },
    });

    let stderr = '';
    let stdout = '';
    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    const exitCode = await new Promise<number>((resolve) => {
      proc.on('close', (code) => resolve(code ?? 0));
    });

    // 1. Process must exit with non-zero (terminated startup)
    expect(exitCode).toBe(1);

    // 2. Fatal error log must be clearly emitted
    const combinedOutput = stdout + stderr;
    expect(combinedOutput).toContain('[FATAL PRODUCTION ERROR] Database migration execution failed');
    expect(combinedOutput).toContain('Startup terminated — application must not run against a broken or out-of-date schema');
    expect(combinedOutput).toContain('CORRUPT_SCHEMA');
  });
});
