import pg from 'pg';
import { RateLimiterEngine } from '@caim/auth/rate-limiter.ts';

const { Pool } = pg;

let pool: pg.Pool | null = null;
let engine: RateLimiterEngine | null = null;

process.on('message', async (message: any) => {
  try {
    if (message.action === 'init') {
      const dbUrl = message.dbUrl || process.env.TEST_DB_URL;
      pool = new Pool({
        connectionString: dbUrl,
        max: 5,
        idleTimeoutMillis: 10000,
        connectionTimeoutMillis: 5000,
      });

      pool.on('error', (err) => {
        // Suppress idle connection / disconnect errors from in-memory test database
      });

      engine = new RateLimiterEngine({ dbClient: pool as any });

      // Verify connection by running a simple ping query
      await pool.query('SELECT 1;');

      process.send?.({
        action: 'ready',
        pid: process.pid,
      });
      return;
    }

    if (message.action === 'check') {
      if (!engine) {
        throw new Error(`Worker (PID: ${process.pid}) has not been initialized`);
      }
      const checkResult = await engine.checkLimit(message.request);
      process.send?.({
        action: 'checkResult',
        requestId: message.requestId,
        pid: process.pid,
        allowed: checkResult.allowed,
        remaining: checkResult.remaining,
        callerKey: checkResult.callerKey,
      });
      return;
    }

    if (message.action === 'close') {
      if (pool) {
        await pool.end().catch(() => {});
      }
      process.send?.({
        action: 'closed',
        pid: process.pid,
      });
      setTimeout(() => {
        process.exit(0);
      }, 50);
    }
  } catch (err: any) {
    process.send?.({
      action: 'error',
      requestId: message.requestId,
      pid: process.pid,
      error: err.message || String(err),
    });
  }
});
